"""
test_panels_suite.py
====================

Everything that must hold for the three panels, as runnable assertions.

    python test_panels_suite.py             # logic + intake + schema (fast)
    python test_panels_suite.py --llm       # also runs the local model
    python test_panels_suite.py --ui        # also drives the Tk widgets

Sections:

  A  INTAKE      hostile and malformed files are refused, cosmetically
                 different but valid files are accepted
  B  PANEL 1     every number is recomputable from the predictions
  C  FINDINGS    aggregation is consistent with the per-flow predictions
  D  PANEL 2     attributions describe the row and class they claim to
  E  PANEL 3     citations exist, missing documents are named, nothing is
                 invented
  F  SCHEMA      the grounding checks catch what they are meant to catch
  G  LLM         narration is additive and its provenance is recorded
  H  UI          the widgets fill and follow the selection
  I  PCAP        a capture converts to the exact schema the model needs,
                 and which engine converted it is recorded

No framework. A failure prints what was expected and what happened; the
exit code is the number of failures.
"""

import os
import sys
import argparse
import tempfile

import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

SAMPLE = os.path.join(HERE, "sample_data", "sample_flows.csv")
SAMPLE_FULL = os.path.join(HERE, "sample_data", "sample_flows_full.csv")

FAILURES = []
CHECKS = 0


def check(name, ok, detail=""):
    global CHECKS
    CHECKS += 1
    if ok:
        print(f"  pass  {name}")
    else:
        print(f"  FAIL  {name}" + (f"\n          {detail}" if detail else ""))
        FAILURES.append(name)
    return ok


def section(title):
    print(f"\n{title}\n{'-' * len(title)}")


# ============================================================
# A -- INTAKE
# ============================================================

def test_intake():
    section("A  INTAKE")
    from services.panels_service import build_panels, load_bundle
    from services.flow_intake import normalise_columns

    feats = load_bundle()["features"]
    tmp = tempfile.mkdtemp()
    good = pd.read_csv(SAMPLE, nrows=40)

    def refuse(name, make):
        path = os.path.join(tmp, name)
        make(path)
        r = build_panels(path, name)
        check(f"refuses {name}", "error" in r,
              f"accepted a file it should not have")

    refuse("empty.csv", lambda p: open(p, "w").close())
    refuse("headers_only.csv", lambda p: good.head(0).to_csv(p, index=False))
    refuse("binary.bin", lambda p: open(p, "wb").write(os.urandom(4096)))
    refuse("wrong_cols.csv",
           lambda p: pd.DataFrame({"a": [1], "b": [2]}).to_csv(p, index=False))
    refuse("a_directory", lambda p: os.makedirs(p, exist_ok=True))
    refuse("mostly_text.csv",
           lambda p: good.assign(**{c: "zz" for c in feats[:40]})
                         .to_csv(p, index=False))

    r = build_panels(os.path.join(tmp, "does_not_exist.csv"), "x")
    check("refuses a missing path", "error" in r)

    # Cosmetic differences must NOT be refused.
    messy = os.path.join(tmp, "messy.csv")
    d = good.copy()
    d.columns = [f"  {c} " for c in d.columns]
    d = d.rename(columns={"  CWR Flag Count ": "CWE Flag Count"})
    d["an_extra_column"] = 1
    d.to_csv(messy, index=False)
    r = build_panels(messy, "messy.csv")
    check("accepts padded headers, old CWE spelling and an extra column",
          "error" not in r, r.get("error", ""))

    nd = normalise_columns(pd.DataFrame(columns=["CWE Flag Count",
                                                 "CWR Flag Cnt", " Dst Port "]))
    check("CWE and CWR fold to one column",
          list(nd.columns) == ["CWR Flag Count", "Dst Port"],
          f"got {list(nd.columns)}")


# ============================================================
# B / C / D / E -- PANEL LOGIC
# ============================================================

def _load(path=SAMPLE_FULL):
    import services.panels_service as ps
    from services.flow_intake import read_flows
    b = ps.load_bundle()
    flows, _ = read_flows(path, b["features"])
    X, proba, k, names, _ = ps.classify(flows, b)
    return ps, b, flows, X, proba, k, names


def test_panel1():
    section("B  PANEL 1 -- flow summary")
    ps, b, flows, X, proba, k, names = _load()
    f = ps.summarise_capture(flows, names, proba, "x.pcap")["facts"]

    check("class counts sum to total",
          sum(f["class_counts"].values()) == f["total_flows"])
    check("benign + attack == total",
          f["benign_flows"] + f["attack_flows"] == f["total_flows"])
    # attack_share is stored rounded to 4dp, so compare at that precision.
    check("attack share matches the counts",
          abs(f["attack_share"] - round(f["attack_flows"] / f["total_flows"], 4))
          < 1e-9)
    check("distinct attack classes excludes Benign",
          f["distinct_attack_classes"]
          == len([c for c in f["class_counts"] if c != "Benign"]))
    check("low-confidence count matches the threshold",
          f["low_confidence_flows"] == int((proba.max(1) < 0.60).sum()))

    w = f.get("capture_window")
    check("capture window is present when Timestamp is", bool(w))
    if w:
        check("span is not negative", w["span_seconds"] >= 0)
        # Flows overlap, so the sum of durations always exceeds the span.
        check("span is smaller than the sum of flow durations",
              w["span_seconds"] <= f["total_flow_seconds"])
        check("dates parse day-first (CICFlowMeter writes dd/mm/yyyy)",
              w["first_flow"].startswith("2026-09-08"),
              f"got {w['first_flow']}")

    e = f.get("endpoints", {})
    check("endpoints are reported when IP columns exist", bool(e.get("targets")))
    if e.get("targets"):
        top = e["targets"][0]
        actual = int((flows["Dst IP"].astype(str) == top["address"]).sum())
        check("busiest target count is correct", top["flows"] == actual,
              f"{top['flows']} vs {actual}")

    # Without identity columns the panel must degrade, not guess.
    f2 = ps.summarise_capture(
        pd.read_csv(SAMPLE), names, proba, "x")["facts"]
    check("no capture window claimed without Timestamp",
          "capture_window" not in f2)


def test_findings():
    section("C  FINDINGS -- aggregation")
    ps, b, flows, X, proba, k, names = _load()
    facts = ps.summarise_capture(flows, names, proba, "x")["facts"]
    fs = ps.aggregate(names, proba, k, b, flows)

    check("flow counts sum to the attack total",
          sum(x["flow_count"] for x in fs) == facts["attack_flows"])
    check("Benign is never a finding",
          all(x["class"] != "Benign" for x in fs))
    check("findings are sorted by flow count, descending",
          all(a["flow_count"] >= b_["flow_count"]
              for a, b_ in zip(fs, fs[1:])))
    check("every confidence_mean recomputes from the predictions",
          all(abs(x["confidence_mean"]
                  - proba[names == x["class"], k[names == x["class"]]].mean())
              < 1e-4 for x in fs))
    check("representative rows are valid indices",
          all(0 <= r < len(names) for x in fs for r in x["representative_rows"]))
    check("representative rows belong to their own class",
          all(names[r] == x["class"]
              for x in fs for r in x["representative_rows"]))
    check("first representative is the most confident, second the least",
          all(proba[x["representative_rows"][0], k[x["representative_rows"][0]]]
              >= proba[x["representative_rows"][1], k[x["representative_rows"][1]]]
              for x in fs))
    check("runner-up share is a proportion",
          all(0 <= x["dominant_runner_up_share"] <= 1 for x in fs))
    check("host attribution is attached when IP columns exist",
          all("endpoints" in x for x in fs))


def test_panel2():
    section("D  PANEL 2 -- SHAP attributions")
    ps, b, flows, X, proba, k, names = _load()
    fs = ps.aggregate(names, proba, k, b, flows)
    sp = ps.explain_detections(X, proba, k, names, b,
                               fs[0]["representative_rows"])

    check("units are declared as log-odds", "log-odds" in sp["units"])

    for d in sp["detections"]:
        r = d["row"]
        tag = f"row {r}"
        check(f"{tag}: predicted class matches classify()",
              d["predicted"] == names[r])
        check(f"{tag}: confidence matches predict_proba",
              abs(d["confidence"] - proba[r, k[r]]) < 1e-4)
        check(f"{tag}: runner-up is the second highest probability",
              abs(d["runner_up_confidence"] - np.sort(proba[r])[-2]) < 1e-4)
        check(f"{tag}: attributions are ranked by magnitude",
              all(abs(a["contribution"]) >= abs(c["contribution"])
                  for a, c in zip(d["attributions"], d["attributions"][1:])))
        # The displayed value must be the ORIGINAL cell, not the scaled one.
        a0 = d["attributions"][0]
        orig = float(pd.to_numeric(flows[a0["feature"]],
                                   errors="coerce").fillna(0.0).iloc[r])
        check(f"{tag}: raw_value is the original CSV value",
              abs(a0["raw_value"] - orig) < max(1e-2, abs(orig) * 1e-4),
              f"{a0['raw_value']} vs {orig}")
        check(f"{tag}: every feature has a plain-English label",
              all(a["plain"] != a["feature"] for a in d["attributions"]))


def test_panel3():
    section("E  PANEL 3 -- recommendations")
    import services.panels_service as ps
    _, b, flows, X, proba, k, names = _load()
    fs = ps.aggregate(names, proba, k, b, flows)

    by_class = {x["class"]: x for x in fs}

    if "Slowloris" in by_class:
        rec = ps.recommend(by_class["Slowloris"])
        check("a class cites its own document",
              "incident_response/slowloris.md" in rec["citations"],
              str(rec["citations"]))
        # Now that Slowloris and DoS have separate files, the ambiguity
        # retrieval finally has two documents to pull rather than one shared
        # one. Both playbooks reaching the panel is the point of it.
        check("an ambiguous pair retrieves both playbooks",
              "incident_response/dos.md" in rec["citations"],
              str(rec["citations"]))
        # Assert a durable property, not the sample text: the retrieved
        # document must reach the panel with its own provenance header
        # intact. Checking for placeholder wording coupled this test to one
        # file's contents and broke the moment that file was replaced.
        quoted = [s["body"] for s in rec["sections"] if s.get("source")]
        check("the document is quoted with its provenance header",
              quoted and any("Source:" in q or "> Source" in q
                             for q in quoted),
              "no source line survived into the panel")
        check("Slowloris reports its ambiguity with DoS",
              rec["ambiguity"] and "DoS" in rec["ambiguity"])

    missing = next((x for x in fs
                    if not os.path.isfile(os.path.join(
                        ps.KNOWLEDGE_DIR,
                        ps.KNOWLEDGE_MAP[x["class"]]["doc"] or ""))), None)
    if missing:
        rec = ps.recommend(missing)
        check(f"{missing['class']} names its missing document",
              bool(rec["missing_documents"]))
        check(f"{missing['class']} offers no guidance without a source",
              not rec["citations"])

    # Every recommendation must carry the work it came from. A response
    # step without its source is an assertion; with the citation it is
    # something an investigator can check.
    uncited = []
    for cls in ps.KNOWLEDGE_MAP:
        if cls == "Benign":
            continue
        stub = {"class": cls, "flow_count": 1, "share_of_capture": 0.01,
                "confidence_mean": 0.8, "confidence_min": 0.8,
                "confidence_max": 0.8, "low_confidence_count": 0,
                "dominant_runner_up": None, "dominant_runner_up_share": 0.0,
                "reliability_f1": None}
        x = ps.recommend(stub)
        if x["citations"] and not x.get("references"):
            uncited.append(cls)
    check("every quoted document carries an IEEE citation",
          not uncited, f"no citation for: {uncited}")

    # One document per class. A file covering several classes cannot be
    # specific to any of them, and the panel quotes the whole file.
    docs = [e["doc"] for e in ps.KNOWLEDGE_MAP.values() if e["doc"]]
    check("every class has its own document, none shared",
          len(docs) == len(set(docs)) == len(ps.KNOWLEDGE_MAP),
          f"{len(docs)} documents for {len(ps.KNOWLEDGE_MAP)} classes")

    check("every model class has a KNOWLEDGE_MAP entry",
          all(c in ps.KNOWLEDGE_MAP for c in b["encoder"].classes_))
    check("an unmapped class raises rather than guessing",
          _raises(lambda: ps.recommend({"class": "NotAClass"})))
    check("MITRE lists are either empty or look like technique IDs",
          all(all(m.startswith("T1") for m in e["mitre"])
              for e in ps.KNOWLEDGE_MAP.values()))


def _raises(fn):
    try:
        fn()
        return False
    except Exception:
        return True


# ============================================================
# F -- GROUNDING SCHEMA
# ============================================================

def test_schema():
    section("F  SCHEMA -- grounding checks catch what they should")
    from services.narration_schema import check as ground

    prompt = ("total_flows: 1500\n  attack_flows: 1283\n"
              "  +3.597  shortest gap between any two packets")
    sources = ["incident_response/denial_of_service.md"]

    clean = ("The capture holds 1500 flows, of which 1283 were flagged. "
             "The strongest evidence was the gap between packets.")
    f, s = ground(clean, prompt, sources)
    check("a grounded narration produces no findings", not f, str(f))

    f, _ = ground("This raised the probability by 42% of the confidence.",
                  prompt, sources)
    check("catches a log-odds value written as a percentage",
          any(x["check"] == "units" for x in f))

    f, _ = ground("See incident_response/made_up_playbook.md for details.",
                  prompt, sources)
    check("catches a citation that was never supplied",
          any(x["check"] == "citation" for x in f))

    f, _ = ground("There were 98765 flows from 4321 distinct hosts.",
                  prompt, sources)
    check("catches figures absent from the input",
          any(x["check"] == "figures" for x in f))

    f, _ = ground("It cites incident_response/denial_of_service.md.",
                  prompt, sources)
    check("does not flag a citation that WAS supplied",
          not any(x["check"] == "citation" for x in f))

    f, _ = ground("Roughly 1,500 flows were seen.", prompt, sources)
    check("tolerates a supplied number written with a comma",
          not any(x["check"] == "figures" for x in f), str(f))


# ============================================================
# G -- LLM
# ============================================================

def test_llm():
    section("G  LLM -- narration is additive and audited")
    from services.panels_service import build_panels
    from services.llm_provider import get_provider

    ok, detail = get_provider("ollama").available()
    if not check("a local model is reachable", ok, detail):
        return

    plain = build_panels(SAMPLE_FULL, "x.pcap")
    narr = build_panels(SAMPLE_FULL, "x.pcap", narrate_with="ollama")

    check("facts are unchanged by narration",
          plain["summary"]["facts"] == narr["summary"]["facts"])
    check("findings are unchanged by narration",
          plain["findings"] == narr["findings"])
    check("attributions are unchanged by narration",
          plain["shap"]["detections"][0]["attributions"]
          == narr["shap"]["detections"][0]["attributions"])
    check("quoted documents are unchanged by narration",
          [s["body"] for s in plain["recommend"]["sections"] if s.get("source")]
          == [s["body"] for s in narr["recommend"]["sections"]
              if s.get("source")])

    # Panel 3 is deterministic by default: its content is a quoted playbook,
    # and a quote cannot be invented.
    check("panel 3 is not narrated by default",
          not narr["recommend"].get("narrative"),
          "recommendations were narrated without being asked for")
    check("only panels 1 and 2 are narrated by default",
          narr.get("narrated_panels") == ["summary", "shap"],
          str(narr.get("narrated_panels")))

    from services.narration_service import ALL_PANELS
    explicit = build_panels(SAMPLE_FULL, "x.pcap", narrate_with="ollama",
                            narrate_panels=ALL_PANELS)
    check("panel 3 narrates when explicitly asked",
          bool(explicit["recommend"].get("narrative")))
    check("the document stays quoted verbatim even when narrated",
          [s["body"] for s in plain["recommend"]["sections"] if s.get("source")]
          == [s["body"] for s in explicit["recommend"]["sections"]
              if s.get("source")])

    for key in ("summary", "shap"):
        p = narr[key]
        check(f"{key}: a narration was produced",
              bool(p.get("narrative")), p.get("narration_error", ""))
        check(f"{key}: provenance was recorded",
              bool(p.get("narration_provenance", {}).get("prompt_sha256_12")))
        check(f"{key}: a verdict was recorded",
              bool(p.get("narration_verdict")))
        check(f"{key}: no HIGH-severity grounding finding",
              not any(x["severity"] == "high"
                      for x in p.get("narration_findings", [])),
              str(p.get("narration_findings")))


# ============================================================
# H -- UI
# ============================================================

def test_ui():
    section("H  UI -- widgets fill and follow the selection")
    import tkinter as tk
    from tkinter import ttk
    from views.xai_tab import XaiTab

    root = tk.Tk()
    root.geometry("1300x850+4000+4000")
    nb = ttk.Notebook(root)
    nb.pack(fill="both", expand=True)
    tab = XaiTab(nb, "ForenXAI_Cases")

    case = {"case_id": "CASE_TEST", "pcap_sha256": "0" * 64,
            "pcap_path": "x.pcap", "generated_csv_path": SAMPLE_FULL,
            "total_flows": 1500, "benign_flows": 217, "threat_flows": 1283}

    state = {"phase": 0}

    def body(w):
        return w.get("1.0", tk.END).strip()

    def tick():
        if state["phase"] == 0 and tab.panels:
            check("summary widget filled", len(body(tab.txt_summary)) > 300)
            check("shap widget filled", len(body(tab.txt_shap)) > 300)
            check("recommend widget filled", len(body(tab.txt_recommend)) > 300)
            check("findings listed", tab.lst_findings.size() > 0)
            check("units stated in the SHAP panel",
                  "log-odds" in body(tab.txt_shap))
            check("narration is off by default", not tab.narrate.get())
            state["first"] = tab.panels["selected"]["class"]
            if tab.lst_findings.size() > 2:
                tab.lst_findings.selection_clear(0, tk.END)
                tab.lst_findings.selection_set(2)
                tab._on_finding_selected()
                state["phase"] = 1
            else:
                state["phase"] = 2
        elif (state["phase"] == 1
              and tab.panels["selected"]["class"] != state["first"]):
            check("selecting a finding rebuilds panels 2 and 3",
                  tab.panels["selected"]["class"] in body(tab.txt_recommend))
            state["phase"] = 2

        if state["phase"] == 2:
            root.quit()
            return
        root.after(150, tick)

    tab.update_xai_results(case, None)
    root.after(300, tick)
    root.after(90_000, root.quit)
    root.mainloop()

    if state["phase"] != 2:
        check("the UI finished within 90 s", False)


# ============================================================
# I  PCAP -- the capture intake path
# ============================================================

def _synthetic_pcap(path):
    """
    Build a small capture with known contents.

    Deterministic and self-contained, so the check does not depend on a
    sample capture being present on any particular machine. It carries a TCP
    conversation with URG set and CWR clear, which is what makes the CWR
    check below meaningful.
    """
    from scapy.all import IP, TCP, UDP, Ether, wrpcap

    pkts = []
    t = 1_700_000_000.0

    # Explicit MACs: letting scapy fill them makes it try to resolve the
    # destination on the live network, which it cannot do here.
    mac_a, mac_b = "02:00:00:00:00:01", "02:00:00:00:00:02"

    # TCP: handshake, data packets with URG, then teardown. The URG packets
    # sit on EVEN indices so they travel in the forward direction, which is
    # what the CWR check needs.
    flags = ["S", "SA", "PAU", "A", "PAU", "A", "FA", "A"]
    for i, fl in enumerate(flags):
        forward = i % 2 == 0
        p = (
            Ether(src=mac_a if forward else mac_b,
                  dst=mac_b if forward else mac_a)
            / IP(src="10.0.0.1" if forward else "10.0.0.2",
                 dst="10.0.0.2" if forward else "10.0.0.1")
            / TCP(sport=44_444 if forward else 80,
                  dport=80 if forward else 44_444,
                  flags=fl, urgptr=1 if "U" in fl else 0)
            / (b"x" * 40 if "P" in fl else b"")
        )
        p.time = t + i * 0.01
        pkts.append(p)

    # UDP: a DNS-shaped exchange, so the table is not TCP-only.
    for i in range(4):
        forward = i % 2 == 0
        p = (
            Ether(src=mac_a if forward else mac_b,
                  dst=mac_b if forward else mac_a)
            / IP(src="10.0.0.1" if forward else "10.0.0.53",
                 dst="10.0.0.53" if forward else "10.0.0.1")
            / UDP(sport=55_555 if forward else 53,
                  dport=53 if forward else 55_555)
            / (b"q" * 30)
        )
        p.time = t + 1.0 + i * 0.02
        pkts.append(p)

    wrpcap(path, pkts)
    return len(pkts)


def test_pcap():
    section("I  PCAP -- capture intake")

    import joblib

    from services import cicflowmeter_service as cfm
    from services import pyflow_extractor as pfe

    check("the Python flow extractor imports",
          pfe.AVAILABLE, pfe.IMPORT_ERROR or "")

    if not pfe.AVAILABLE:
        return

    features = joblib.load(
        os.path.join(HERE, "models", "forenxai", "features.pkl"))

    missing, extra = pfe.check_schema(features)
    check("emits every feature the model requires", not missing,
          f"missing: {missing}")
    check("the only extra columns are the forensic identity columns",
          set(extra) == {"Src IP", "Dst IP", "Src Port", "Timestamp"},
          f"extra: {extra}")

    tmp = tempfile.mkdtemp(prefix="forenxai_pcap_")
    pcap = os.path.join(tmp, "synthetic.pcap")
    out = os.path.join(tmp, "synthetic_Flow.csv")

    written = _synthetic_pcap(pcap)
    pfe.extract(pcap, out)

    df = pd.read_csv(out)
    check("a capture with TCP and UDP yields flows", len(df) >= 2,
          f"{written} packets in, {len(df)} flows out")

    check("column names are the CICFlowMeter v4 names the model expects",
          not set(features) - set(df.columns),
          f"absent: {sorted(set(features) - set(df.columns))[:5]}")

    # The upstream cicflowmeter port sets CWR Flag Count to the forward URG
    # count. This capture sets URG and never sets CWR, so if the correction
    # were dropped CWR would read nonzero here.
    urg = df["Fwd URG Flags"].sum()
    cwr = df["CWR Flag Count"].sum()
    check("CWR is counted, not copied from Fwd URG",
          urg > 0 and cwr == 0,
          f"Fwd URG={urg}, CWR={cwr}")

    # Six columns are emitted by identity. Verified as exact against 300,000
    # real CICFlowMeter rows and 1,120,000 training rows; asserted here so a
    # later edit cannot quietly break the relationship.
    for a, b in [("Subflow Fwd Packets", "Total Fwd Packet"),
                 ("Subflow Bwd Packets", "Total Bwd packets"),
                 ("Subflow Fwd Bytes", "Total Length of Fwd Packet"),
                 ("Subflow Bwd Bytes", "Total Length of Bwd Packet"),
                 ("Fwd Segment Size Avg", "Fwd Packet Length Mean"),
                 ("Bwd Segment Size Avg", "Bwd Packet Length Mean")]:
        check(f"{a} == {b}",
              bool(np.allclose(df[a], df[b], rtol=1e-6, atol=1e-6)))

    # The whole point: the extracted CSV must survive intake unchanged.
    from services.flow_intake import read_flows, to_matrix
    flows, report = read_flows(out, features)
    X, mreport = to_matrix(flows, features)
    check("the extracted CSV passes intake", report["rows"] == len(df))
    check("every value reads as a number",
          mreport["coerced_to_zero"] == 0,
          f"{mreport['coerced_to_zero']} cells coerced")
    check("the matrix is the model's shape", X.shape == (len(df), 74),
          str(X.shape))

    # Engine selection must be honest about what is installed.
    status = cfm.java_engine_status()
    check("java_engine_status reports what is missing",
          isinstance(status.get("missing"), list)
          and status["available"] == (not status["missing"]))

    # Full service path, including the provenance record.
    case = os.path.join(tmp, "case")
    df2, csv2 = cfm.extract_flows_from_pcap(pcap, case)
    check("extract_flows_from_pcap returns a populated table", len(df2) > 0)
    check("the engine is recorded on the table",
          df2.attrs.get("flow_engine") in ("java", "python"))
    check("flow_extraction.json is written beside the CSV",
          os.path.isfile(os.path.join(case, "flow_extraction.json")))

    from services.panels_service import read_extraction_record, _engine_lines
    rec = read_extraction_record(csv2)
    check("the provenance record reads back",
          bool(rec) and rec["engine"] == df2.attrs["flow_engine"])
    check("the summary names the extractor",
          any("extracted by" in ln for ln in _engine_lines(rec)))

    # A record describing a different CSV must not be attached to this one.
    other = os.path.join(case, "unrelated_Flow.csv")
    df2.head(1).to_csv(other, index=False)
    check("a provenance record is not applied to a CSV it does not name",
          read_extraction_record(other) is None)


# ============================================================
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--llm", action="store_true",
                    help="also run the local language model (slow)")
    ap.add_argument("--ui", action="store_true",
                    help="also drive the Tk widgets")
    ap.add_argument("--all", action="store_true")
    args = ap.parse_args()

    if not os.path.isfile(SAMPLE_FULL):
        print(f"Missing {SAMPLE_FULL}. It is generated by the fixture step "
              f"in the branch notes.")
        return 2

    test_intake()
    test_panel1()
    test_findings()
    test_panel2()
    test_panel3()
    test_schema()
    test_pcap()

    if args.llm or args.all:
        test_llm()
    if args.ui or args.all:
        test_ui()

    print(f"\n{CHECKS - len(FAILURES)}/{CHECKS} checks passed")
    if FAILURES:
        print("FAILED:")
        for f in FAILURES:
            print(f"  - {f}")
    return len(FAILURES)


if __name__ == "__main__":
    sys.exit(main())
