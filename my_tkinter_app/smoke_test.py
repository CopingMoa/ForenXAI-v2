"""
smoke_test.py
=============

End-to-end checks that the three panels work on real input, follow that
input rather than a fixture, and reach the widgets intact.

    python smoke_test.py           # fast: no language model
    python smoke_test.py --llm     # also narrate, and check the prose
    python smoke_test.py --ui      # also render through the Tk widgets

WHAT THIS IS FOR, AND WHAT IT IS NOT
test_panels_suite.py is the detailed suite: it checks each rule in each
component. This is the smoke test -- it runs the whole path a user takes,
from a CSV to rendered text, and fails loudly if any joint between two
layers has come apart. It is meant to be quick enough to run before every
commit.

The dynamism section exists because a panel that is right on the sample
capture and identical on every other one is not analysing anything. Each
check here feeds DIFFERENT input and asserts the output moved with it.
"""

import argparse
import os
import sys
import tempfile
import warnings

warnings.filterwarnings("ignore")

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import pandas as pd                                        # noqa: E402

from services.panels_service import (build_panels, load_bundle,   # noqa: E402
                                     KNOWLEDGE_MAP)

CHECKS = 0
FAILURES = []


def check(name, ok, detail=""):
    global CHECKS
    CHECKS += 1
    if ok:
        print(f"  pass  {name}")
    else:
        FAILURES.append(name)
        print(f"  FAIL  {name}")
        if detail:
            print(f"          {detail}")


def section(title):
    print(f"\n{title}\n" + "-" * (len(title) + 1))


def _sample():
    full = os.path.join(HERE, "sample_data", "sample_flows_full.csv")
    return full if os.path.isfile(full) else os.path.join(
        HERE, "sample_data", "sample_flows.csv")


# ============================================================
# A -- THE PATH RUNS AT ALL
# ============================================================
def test_end_to_end(sample):
    section("A  END TO END  a CSV becomes three panels")
    r = build_panels(sample, "smoke.pcap")

    check("no error from a valid capture", not r.get("error"), str(r.get("error")))
    for key in ("summary", "shap", "recommend", "selected"):
        check(f"{key} panel was built", bool(r.get(key)))

    facts = r["summary"]["facts"]
    check("flow count is positive", facts["total_flows"] > 0)
    check("benign and attack sum to the total",
          facts["benign_flows"] + facts["attack_flows"] == facts["total_flows"],
          f"{facts['benign_flows']} + {facts['attack_flows']} "
          f"!= {facts['total_flows']}")
    # Tolerance is 1e-4 because the panel rounds the share to four places
    # for display; anything larger than that is a real disagreement between
    # the share and the counts it is derived from.
    check("attack share matches the counts",
          abs(facts["attack_share"]
              - facts["attack_flows"] / facts["total_flows"]) < 1e-4,
          f"{facts['attack_share']} vs "
          f"{facts['attack_flows'] / facts['total_flows']}")
    return r


# ============================================================
# B -- THE PANELS FOLLOW THE INPUT
# ============================================================
def test_dynamic(sample):
    """Different capture, different answer. Nothing here is fixture-shaped."""
    section("B  DYNAMIC  the panels analyse the input, not a fixture")
    df = pd.read_csv(sample)
    tmp = tempfile.mkdtemp()

    def build(name, frame, **kw):
        p = os.path.join(tmp, name + ".csv")
        frame.to_csv(p, index=False)
        return build_panels(p, name + ".pcap", **kw)

    full = build_panels(sample, "full.pcap")
    small = build("small", df.head(200))

    check("a different capture gives a different flow count",
          small["summary"]["facts"]["total_flows"]
          != full["summary"]["facts"]["total_flows"])
    check("the counts are the ones in the file",
          small["summary"]["facts"]["total_flows"] == 200,
          str(small["summary"]["facts"]["total_flows"]))

    def playbooks(res):
        return sorted(s["source"] for s in res["recommend"]["sections"]
                      if (s.get("source") or "").startswith("incident_response/"))

    if small["selected"]["class"] != full["selected"]["class"]:
        check("a different dominant class retrieves a different playbook",
              playbooks(small) != playbooks(full),
              f"{playbooks(small)} vs {playbooks(full)}")

    alt = build_panels(sample, "full.pcap", finding_index=1)
    check("selecting another finding changes the class",
          alt["selected"]["class"] != full["selected"]["class"],
          f"{alt['selected']['class']} vs {full['selected']['class']}")
    check("and retrieves that class's playbook",
          any(full["selected"]["class"].lower() not in p for p in playbooks(alt))
          or playbooks(alt) != playbooks(full),
          f"{playbooks(alt)} vs {playbooks(full)}")

    # The classes come from the model, not from a list in the source.
    enc = list(load_bundle()["encoder"].classes_)
    check("every class the model can output has a playbook entry",
          all(c in KNOWLEDGE_MAP for c in enc),
          str([c for c in enc if c not in KNOWLEDGE_MAP]))
    check("the knowledge map defines no class the model cannot output",
          all(c in enc for c in KNOWLEDGE_MAP),
          str([c for c in KNOWLEDGE_MAP if c not in enc]))
    check("all 15 attack classes and Benign are covered", len(enc) == 16,
          str(len(enc)))


# ============================================================
# C -- BAD INPUT IS REFUSED, NOT GUESSED AT
# ============================================================
def test_hostile(sample):
    section("C  INPUT  a capture that cannot be analysed is refused")
    df = pd.read_csv(sample)
    tmp = tempfile.mkdtemp()

    def build(name, frame):
        p = os.path.join(tmp, name + ".csv")
        frame.to_csv(p, index=False)
        try:
            return build_panels(p, name + ".pcap")
        except Exception as e:
            return {"raised": f"{type(e).__name__}: {e}"}

    empty = build("empty", df.head(0))
    check("a header-only file is refused with a reason",
          bool(empty.get("error")) and not empty.get("raised"),
          str(empty)[:90])

    missing = build("missing", df.head(50).drop(columns=[df.columns[3]]))
    check("a missing feature column is refused, not filled in",
          bool(missing.get("error")) and not missing.get("raised"),
          str(missing)[:90])
    check("the refusal says how many features are missing",
          "74" in str(missing.get("error", "")), str(missing.get("error"))[:90])

    one = build("one", df.head(1))
    check("a single-flow capture still produces panels",
          not one.get("error") and bool(one.get("selected")), str(one)[:90])


# ============================================================
# D -- SHAP EXPLAINS THE DECISION THAT WAS MADE
# ============================================================
def test_shap(result):
    """The property that makes an attribution checkable rather than decorative."""
    section("D  SHAP  the attributions reconstruct the model's own output")
    for d in result["shap"]["detections"]:
        c = d.get("shap_check") or {}
        check(f"row {d['row']}: base + contributions == the model's margin",
              c.get("agrees") is True,
              f"error {c.get('additivity_error')}")
        check(f"row {d['row']}: additivity error is negligible",
              (c.get("additivity_error") or 1) < 1e-3,
              str(c.get("additivity_error")))
        check(f"row {d['row']}: the reconstruction picks the predicted class",
              c.get("reconstruction_picks_predicted") is True)
        check(f"row {d['row']}: every attribution states its direction",
              all(a.get("direction") in ("supports", "argues against")
                  for a in d["attributions"]))
        check(f"row {d['row']}: the predicted class is the top probability",
              d["predicted"] == d["model_output"]["probabilities"][0]["class"],
              f"{d['predicted']} vs {d['model_output']['probabilities'][0]}")


# ============================================================
# E -- EVERY QUOTED DOCUMENT STILL MATCHES ITS SOURCE
# ============================================================
def test_sources(result):
    section("E  SOURCES  retrieved documents are verified, not trusted")
    rec = result["recommend"]
    check("no document was quarantined as unverifiable",
          not rec.get("unverified_documents"),
          str(rec.get("unverified_documents")))
    check("at least one response playbook was retrieved",
          any((s.get("source") or "").startswith("incident_response/")
              for s in rec["sections"]))
    check("every retrieved document has at least one verified quote",
          all(s.get("quotes_verified", 0) > 0 for s in rec["sections"]
              if (s.get("source") or "").startswith("incident_response/")))
    check("references are present for the documents shown",
          bool(rec.get("references")))
    # The SHAP definitions used to be the project's own words while every
    # attack claim carried a citation. NISTIR 8312 closed that: a NIST
    # publication, so rule 2 of fetch_knowledge.SOURCES admits it, and its
    # section 4.2 defines SHAP and Shapley values verbatim.
    #
    # The invariant is now the opposite of what it was. It used to assert
    # that NO source covered SHAP -- true then, and the check fired the
    # moment that stopped being true. What must hold now is that the source
    # is present AND quoted, so removing either is caught rather than
    # quietly returning the corpus to an unsourced definition.
    import fetch_knowledge as fk
    check("a published source defines SHAP",
          "NIST.IR.8312" in fk.SOURCES,
          "NISTIR 8312 is the NIST publication that defines SHAP")
    gloss = open(os.path.join(HERE, "knowledge", "interpretability",
                              "glossary.md"), encoding="utf-8").read()
    check("the glossary quotes it rather than asserting",
          "## From NIST.IR.8312" in gloss and "Shapley values" in gloss,
          "glossary.md no longer quotes NISTIR 8312")
    from services.source_guard import verify_document
    vg = verify_document("interpretability/glossary.md")
    check("every glossary quote verifies against its source",
          vg["ok"], str(vg.get("failures"))[:120])

    check("references are in ACM format, not IEEE",
          all(not r.lstrip().startswith(('A. ', 'D. ', 'K. ', 'T. '))
              or ". 19" in r or ". 20" in r for r in rec["references"]),
          str(rec["references"][:1]))


# ============================================================
# F -- UI READS WHAT THE BACKEND WRITES
# ============================================================
def test_ui_contract(result):
    """The joint that no unit test covers: renderer against real output.

    Every field the widgets read is read here, on the dict the service
    actually returned. A rename on either side fails this rather than
    surfacing as an empty panel at run time.
    """
    section("F  INTEGRATION  the renderers consume the service's output")
    from views.xai_tab import XaiTab

    for name, fn, args in (
            ("panel 1", XaiTab._narration_blocks, (result["summary"],)),
            ("panel 2", XaiTab._narration_blocks, (result["shap"],)),
            ("panel 3", XaiTab._narration_blocks, (result["recommend"],))):
        try:
            blocks = fn(*args)
            ok, detail = True, ""
        except Exception as e:
            blocks, ok, detail = [], False, f"{type(e).__name__}: {e}"
        check(f"{name}: narration renders without raising", ok, detail)
        check(f"{name}: blocks are (text, tag) pairs",
              all(isinstance(b, tuple) and len(b) == 2 for b in blocks))

    for s in result["recommend"]["sections"]:
        if not (s.get("digest") and s.get("source")):
            continue
        try:
            blocks = XaiTab._digest_blocks(s)
            ok, detail = bool(blocks), ""
        except Exception as e:
            ok, detail = False, f"{type(e).__name__}: {e}"
        check(f"section {s['heading'][:34]!r} renders", ok, detail)

    styles = {(s.get("digest") or {}).get("style")
              for s in result["recommend"]["sections"] if s.get("digest")}
    check("each document is digested in a known shape",
          styles <= {"playbook", "explainer", "glossary"}, str(styles))

    panels = {s.get("panel") for s in result["recommend"]["sections"]
              if s.get("kind") == "model"}
    check("guidance is routed to a real panel",
          panels <= {"shap", "recommend"}, str(panels))


# ============================================================
# G -- NARRATION (optional; needs the model)
# ============================================================
def test_narration(sample):
    section("G  NARRATION  prose is checked, and never replaced by an excuse")
    from services.llm_provider import get_provider
    from services import narration_service as ns

    prov = get_provider("ollama")
    ok, detail = prov.available()
    if not ok:
        check("a local model is reachable", False, str(detail))
        return
    check("a local model is reachable", True)

    res = build_panels(sample, "smoke.pcap")
    finding = res["selected"]
    for key in ("summary", "shap", "recommend"):
        p = res[key]
        before = dict(p.get("facts") or {})
        ns.narrate(p, prov, {"finding": finding, "shap": res.get("shap")})

        check(f"{key}: a paragraph is always present",
              bool(p.get("narrative")), str(p.get("narration_error")))
        check(f"{key}: narration did not alter the figures",
              dict(p.get("facts") or {}) == before)
        check(f"{key}: nothing high-severity is left on display",
              not [f for f in p.get("narration_findings", [])
                   if f["severity"] == "high"] or p.get("narration_fallback"),
              str(p.get("narration_findings")))

        text = (p.get("narrative") or "").lower()
        for phrase in ("not shown", "withheld", "could not be traced",
                       "removed from the text"):
            check(f"{key}: the panel does not explain itself ({phrase!r})",
                  phrase not in text, text[:90])


def test_prompt_examples():
    """No worked example may contain material the prompt withholds.

    The examples are in-context learning: a 3B model copies the shape it is
    shown, which is why they earn their tokens and also why what goes in
    them is load-bearing. Two failures came from examples that were too
    concrete -- the recommendations example once used two real lines out of
    dos.md and the model pasted both into a Slowloris answer, and the SHAP
    example named a class ("toward API") while the prompt deliberately
    withholds the class name to stop the model reaching for a protocol.

    An example is part of the prompt. Anything the prompt is careful not to
    say, the example must not say either.
    """
    section("N  PROMPTS  examples do not reintroduce withheld material")
    import re as _re
    from services.narration_service import EXAMPLES
    from services.panels_service import load_bundle

    classes = list(load_bundle()["encoder"].classes_)
    for name, text in EXAMPLES.items():
        hits = [c for c in classes
                if _re.search(r"" + _re.escape(c) + r"", text)]
        check(f"{name}: names no class the model could copy",
              not hits, str(hits))

    shap = EXAMPLES["shap_explanation"]
    check("the SHAP example still teaches the log-odds unit",
          "log-odds" in shap, "the unit lesson was lost with the class name")
    check("the SHAP example still shows the rejected percentage form",
          "%" in shap and "REJECTED" in shap)

    # Panel 3's example must quote no sentence at all, accepted or rejected.
    #
    # A rejected example is still an example: a 3B model copies the shape it
    # is shown and does not reliably carry the minus sign. The model was
    # seen returning "Apply the class playbook" -- a REJECTED form -- as a
    # step. Panel 3's steps are free prose, so a plausible-looking wrong
    # step is not something a later check can recognise; the only defence is
    # that no such sentence exists in the prompt to lift.
    #
    # Panel 2's example is deliberately exempt. Its rejected form has to
    # SHOW the percentage phrasing to teach against it, and if the model
    # copies that, `no_percentage` catches it. The rule is not "never quote"
    # -- it is "never quote something the checks downstream cannot catch".
    rec = EXAMPLES["recommendations"]
    quoted = [q for q in _re.findall(r'"([^"<>]{12,})"', rec)
              if len(q.split()) >= 3]
    check("panel 3's example quotes no usable sentence",
          not quoted, str(quoted))
    check("panel 3's example still shows the rejected shape",
          "REJECTED" in rec and "anchor" in rec)


# ============================================================
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--llm", action="store_true",
                    help="also narrate with the local model")
    ap.add_argument("--ui", action="store_true",
                    help="also drive the Tk widgets")
    ap.add_argument("--all", action="store_true")
    args = ap.parse_args()

    sample = _sample()
    if not os.path.isfile(sample):
        print(f"Missing {sample}")
        return 2
    print(f"Capture under test: {os.path.basename(sample)}")

    result = test_end_to_end(sample)
    test_dynamic(sample)
    test_hostile(sample)
    test_shap(result)
    test_sources(result)
    test_ui_contract(result)
    test_prompt_examples()

    if args.llm or args.all:
        test_narration(sample)

    if args.ui or args.all:
        section("H  WIDGETS  the tab fills without a display error")
        try:
            import tkinter as tk
            from tkinter import ttk
            from views.xai_tab import XaiTab
            root = tk.Tk()
            root.geometry("1200x800+4000+4000")
            nb = ttk.Notebook(root)
            nb.pack(fill="both", expand=True)
            tab = XaiTab(nb, "ForenXAI_Cases")
            tab.panels = result
            tab._render_all(result)
            body = tab.txt_summary.get("1.0", tk.END)
            check("the summary widget filled", len(body.strip()) > 200)
            root.destroy()
        except Exception as e:
            check("the widgets render", False, f"{type(e).__name__}: {e}")

    print(f"\n{CHECKS - len(FAILURES)}/{CHECKS} checks passed")
    if FAILURES:
        print("FAILED:")
        for f in FAILURES:
            print(f"  - {f}")
    return len(FAILURES)


if __name__ == "__main__":
    sys.exit(main())
