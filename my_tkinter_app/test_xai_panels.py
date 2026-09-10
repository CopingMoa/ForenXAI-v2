"""
test_xai_panels.py
==================

Drives XaiTab end to end without a PCAP, so the three panels can be checked
before CICFlowMeter and the forensic pipeline are in the loop.

It builds a real Tk window (positioned off-screen), feeds it a fake case
pointing at sample_data/sample_flows.csv, waits for the background analysis,
and asserts every panel filled. Then it selects a different finding and
checks panels 2 and 3 recompute.

    python test_xai_panels.py            # asserts, writes the report
    python test_xai_panels.py --show     # same, but visible on screen

Results go to test_xai_panels_report.txt as well as stdout, because a Tk
mainloop swallows stdout in some shells.
"""

import os
import sys
import tkinter as tk
from tkinter import ttk

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from services.llm_provider import OLLAMA_MODEL         # noqa: E402
from views.xai_tab import XaiTab                       # noqa: E402


REPORT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "test_xai_panels_report.txt"
)

SAMPLE_CSV = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "sample_data",
    "sample_flows.csv"
)

lines = []


def say(text=""):
    print(text, flush=True)
    lines.append(text)


def body(widget):
    return widget.get("1.0", tk.END).strip()


# Narration dominates this test, and its cost is the model's. 120 s was
# right for qwen2.5:3b at about 5 s a panel; qwen2.5:7b takes about 20 s and
# overran it on the first run after the default changed. The budget is a
# guard against a hang, not a performance assertion, so it is set from the
# model rather than tightened to whatever passes today.
BUDGET = 300_000 if "7b" in OLLAMA_MODEL or "14b" in OLLAMA_MODEL else 120_000


def main():
    show = "--show" in sys.argv

    if not os.path.isfile(SAMPLE_CSV):
        say(f"FAIL: no sample at {SAMPLE_CSV}")
        return 2

    root = tk.Tk()
    root.title("XaiTab panel test")
    # Off-screen unless asked for, so the test can run unattended.
    root.geometry("1300x850+120+60" if show else "1300x850+4000+4000")

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True)

    tab = XaiTab(notebook, "ForenXAI_Cases")

    # The shape ForensicTab hands over. Only generated_csv_path and
    # pcap_path are actually used by the panels.
    case = {
        "case_id": "CASE_TEST_0001",
        "pcap_sha256": "a3f1" + "0" * 60,
        "pcap_path": "sample_capture.pcap",
        "generated_csv_path": SAMPLE_CSV,
        "total_flows": 1500,
        "benign_flows": 217,
        "threat_flows": 1283,
    }

    state = {"phase": 0, "failures": [], "first": None}

    def check_failed(condition, message):
        if not condition:
            state["failures"].append(message)

    def tick():
        # ---- phase 0: first render ------------------------------------
        if state["phase"] == 0 and tab.panels:
            say("PANEL RENDER")
            say(f"  header    {tab.lbl_xai_summary.cget('text')}")
            say(f"  findings  {tab.lst_findings.size()} rows | "
                f"first: {tab.lst_findings.get(0)!r}")

            for name, widget in (("summary", tab.txt_summary),
                                 ("shap", tab.txt_shap),
                                 ("recommend", tab.txt_recommend)):
                text = body(widget)
                head = text.splitlines()[0][:56] if text else "(empty)"
                say(f"  {name:<10}{len(text):>6} chars | {head}")
                check_failed(len(text) > 300, f"{name} panel too short")

            check_failed(tab.lst_findings.size() > 0, "no findings listed")

            sel = tab.panels["selected"]
            state["first"] = sel["class"]
            say("")
            say(f"  selected  {sel['class']}  "
                f"{sel['flow_count']} flows  "
                f"conf {sel['confidence_mean']:.2f}")

            rec = tab.panels["recommend"]
            say(f"  citations {rec['citations'] or 'none'}")
            say(f"  missing   {rec['missing_documents'] or 'none'}")
            if rec["ambiguity"]:
                say(f"  ambiguity {rec['ambiguity'][:70]}...")

            # SHAP units must never be rendered as a percentage.
            shap_text = body(tab.txt_shap)
            check_failed("log-odds" in shap_text,
                         "SHAP panel does not state its units")
            check_failed("%" not in shap_text.split("Contributions are")[-1][:120],
                         "SHAP units line mentions a percentage")

            if tab.lst_findings.size() > 2:
                say("")
                say("SELECTING A DIFFERENT FINDING")
                tab.lst_findings.selection_clear(0, tk.END)
                tab.lst_findings.selection_set(2)
                tab._on_finding_selected()
                state["phase"] = 1
            else:
                state["phase"] = 2

        # ---- phase 1: selection recomputes 2 and 3 --------------------
        elif (state["phase"] == 1
              and tab.panels["selected"]["class"] != state["first"]):
            sel = tab.panels["selected"]
            say(f"  now       {sel['class']}  {sel['flow_count']} flows")
            say(f"  recommend {body(tab.txt_recommend).splitlines()[0][:56]}")
            check_failed(sel["class"] in body(tab.txt_recommend),
                         "recommendations did not follow the selection")
            state["phase"] = 2

        # ---- done ------------------------------------------------------
        if state["phase"] == 2:
            say("")
            if state["failures"]:
                say(f"FAILED ({len(state['failures'])})")
                for f in state["failures"]:
                    say(f"  - {f}")
            else:
                say("PASS - all three panels render and follow the selection")
            with open(REPORT, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
            if not show:
                root.quit()
            return

        root.after(150, tick)

    def give_up():
        if state["phase"] != 2:
            say(f"FAILED: analysis did not finish within {BUDGET // 1000} s")
            with open(REPORT, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
            root.quit()

    tab.update_xai_results(case, None)
    root.after(300, tick)
    root.after(BUDGET, give_up)
    root.mainloop()

    return 1 if state["failures"] or state["phase"] != 2 else 0


if __name__ == "__main__":
    sys.exit(main())
