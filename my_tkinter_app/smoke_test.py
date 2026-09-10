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
                                     KNOWLEDGE_MAP, KNOWLEDGE_DIR)

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
    gloss = open(os.path.join(KNOWLEDGE_DIR, "interpretability",
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
def load_xai_tab():
    """Import XaiTab from the source tree OR from a built handoff.

    In this repository the renderer is views/xai_tab.py. In the folder
    make_handoff.py builds there is no views package -- the file sits in
    xai_tab/, beside the notes for that tab. Section F is the check a UI
    team most needs and it was unrunnable in the copy they are given,
    because the import only knew the first layout.
    """
    try:
        from views.xai_tab import XaiTab
        return XaiTab
    except ModuleNotFoundError:
        import importlib.util
        here = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(here, "xai_tab", "xai_tab.py")
        if not os.path.isfile(path):
            raise
        spec = importlib.util.spec_from_file_location("xai_tab_ref", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.XaiTab


def test_ui_contract(result):
    """The joint that no unit test covers: renderer against real output.

    Every field the widgets read is read here, on the dict the service
    actually returned. A rename on either side fails this rather than
    surfacing as an empty panel at run time.
    """
    section("F  INTEGRATION  the renderers consume the service's output")
    XaiTab = load_xai_tab()

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


def test_direction_check():
    """A negative attribution called supporting -- and nothing else.

    This check withholds the whole paragraph, so a false positive costs the
    reader every sentence on that finding. It had one: a fixed-width window
    ran past the full stop and matched "consistent with the training data"
    in the NEXT sentence, which is a claim about the distribution, not about
    the class. Both halves are asserted here -- the inversion still fires,
    the two correct sentences no longer do.
    """
    section("S  DIRECTION  an inverted sign fires, a distribution claim does not")
    from services.narration_schema import check as grounding

    attrs = [{"plain": "total header bytes in inbound packets",
              "contribution": -0.63},
             {"plain": "shortest gap between any two packets",
              "contribution": 3.60}]

    def fires(text):
        return any(x["check"] == "direction" for x in
                   grounding(text, "prompt", [], attributions=attrs)[0])

    check("an inverted sign is caught",
          fires("Total header bytes in inbound packets, 56, is typical of "
                "this class."))
    check("so is 'supports the prediction'",
          fires("The total header bytes in inbound packets supports the "
                "prediction."))
    check("a training-data comparison in the next sentence does not fire",
          not fires("The total header bytes in inbound packets were typical, "
                    "at 56 bytes. These characteristics are consistent with "
                    "the training data used to build the model."))
    check("nor does one in the same sentence",
          not fires("The total header bytes in inbound packets is consistent "
                    "with the training distribution."))
    check("a positive attribution may support the class",
          not fires("The shortest gap between any two packets supports the "
                    "prediction."))


def test_mechanism_and_scale():
    """Two guards that were quietly failing in opposite directions.

    The mechanism list held "syn flood" and the model wrote "SYN flooding",
    which the trailing word-boundary rejected -- so the one spelling that
    mattered was the one it could not see. And an adjective was cut even
    when the model had quoted the supplied standard-deviation comparison in
    the same breath, which is the model agreeing with its evidence.
    """
    section("T  SCALE  inflections are caught, agreement is not punished")
    from services.narration_schema import (_mechanisms_in,
                                           neutralise_magnitude)

    for text, want in (
            ("indicating potential scanning or SYN flooding activity", True),
            ("consistent with port scanning", True),
            ("evidence of data exfiltration", True),
            ("the server sent data in bursts of 553 bytes", False),
            ("many connection-open requests with few completions", False)):
        check(f"mechanism {'caught' if want else 'clean'}: {text[:38]}",
              bool(_mechanisms_in(text)) == want, str(_mechanisms_in(text)))

    licensed = ("The largest outbound packet was 2,962 bytes, 1.5 standard "
                "deviations above the training mean, suggesting unusually "
                "large packets.")
    paraphrased = licensed.replace("above", "larger than")
    unlicensed = ("The evidence suggests the traffic involved large gaps "
                  "between packets.")
    contradicted = ("The gap of 1.17 seconds is typical for this feature "
                    "and shows large delays between packets.")

    check("an adjective beside the supplied comparison is kept",
          not neutralise_magnitude(licensed)[1])
    check("kept when the model paraphrases 'above' as 'larger than'",
          not neutralise_magnitude(paraphrased)[1])
    check("an adjective with no comparison is cut",
          bool(neutralise_magnitude(unlicensed)[1]))
    check("an adjective contradicting a 'typical' claim is cut",
          bool(neutralise_magnitude(contradicted)[1]))

    # The seam this function leaves is on screen, so it is asserted here.
    # Cutting one word out of "infrequent, large gaps" used to leave
    # "infrequent, gaps" -- a dangling comma in the panel this function
    # exists to protect, reported for weeks as invisible to the reader.
    listed = ("The traffic is characterized by infrequent, large gaps "
              "between packets.")
    out, cut = neutralise_magnitude(listed)
    check("a coordinated list loses its separator with the word",
          ", gaps" not in out and "  " not in out, out)
    check("and loses every unlicensed word in it",
          sorted(cut) == ["infrequent", "large"], str(cut))
    check("a predicative adjective is still left for the check to flag",
          not neutralise_magnitude("The gaps were unusually short.")[1])


def test_prompt_shape(sample):
    """What reaches the model, and what deliberately does not.

    Each of these is a failure that was measured, then fixed by changing
    the evidence rather than the instructions. They are asserted on the
    PROMPT because that is where the fix lives -- no model needed.
    """
    section("P  EVIDENCE  the prompt withholds what the model misreads")
    from services import narration_service as ns

    res = build_panels(sample, "smoke.pcap")
    det = (res["shap"].get("detections") or [{}])[0]
    attrs = det.get("attributions") or []

    seen = {}

    class Spy:
        name, model = "spy", "spy"

        def available(self):
            return True, ""

        def complete(self, system, user, *a, **k):
            seen["user"] = user
            raise RuntimeError("prompt captured")

    p = dict(res["shap"])
    ns.narrate(p, Spy(), {"finding": res["selected"], "shap": res.get("shap")})
    prompt = seen.get("user", "")
    check("the SHAP prompt was captured", bool(prompt))

    cautioned = [a for a in attrs if a.get("caution")]
    if cautioned:
        name = cautioned[0]["plain"].split(" -- ")[0]
        check("a cautioned feature is not named in the prompt",
              name.lower() not in prompt.lower(), name)
        check("its caution text is not in the prompt either",
              cautioned[0]["caution"][:40].lower() not in prompt.lower())
    check("the panel still shows every attribution",
          len(attrs) > len([a for a in attrs if not a.get("caution")]) or
          not cautioned)

    shown = [a for a in attrs if not a.get("caution")]
    values = [a.get("readable") for a in shown]
    if len(values) != len(set(values)):
        check("features sharing a value say so",
              "the same observed value as" in prompt, prompt[:200])

    check("no class name reaches the SHAP prompt",
          (res["selected"].get("class") or "zzz") not in prompt)

    # The prompt used to forbid naming a protocol in a sentence that named
    # two, and the glossary handed over "indicates scanning or SYN
    # flooding". Both put the word in the input, so check 5 scored the
    # model repeating it as MEDIUM rather than HIGH.
    from services.narration_schema import _mechanisms_in
    leaked = sorted(_mechanisms_in(prompt))
    check("no protocol or technique word is in the SHAP prompt",
          not leaked, str(leaked))


def test_progress(sample):
    """The tab can say what it is doing, and cannot be broken by saying it."""
    section("Q  PROGRESS  stages are reported, and a bad callback is inert")
    seen = []
    res = build_panels(sample, "smoke.pcap", on_progress=seen.append)
    check("progress is reported before narration is even requested",
          len(seen) >= 3, str(seen))
    check("a stage names the finding's own figures",
          any(res["selected"]["class"] in m for m in seen), str(seen))

    # A UI callback must never be able to fail an analysis.
    def explode(_):
        raise RuntimeError("callback is broken")

    blown = build_panels(sample, "smoke.pcap", on_progress=explode)
    check("a raising callback does not fail the analysis",
          "error" not in blown and bool(blown.get("summary")))


def test_reset_on_new_capture(sample):
    """A second upload clears the first one's panels, and outruns it.

    Narration takes 45-60 s. That is long enough to load another capture
    while the last is still being explained, and long enough for panels 2
    and 3 to sit there describing evidence the investigator has moved on
    from -- under a header naming the new one.
    """
    section("U  RESET  a new capture does not inherit the last one's panels")
    import tkinter as _tk
    from tkinter import ttk as _ttk
    XaiTab = load_xai_tab()

    try:
        root = _tk.Tk()
        root.geometry("900x600+4000+4000")
        nb = _ttk.Notebook(root)
        nb.pack(fill="both", expand=True)
    except Exception as e:
        check("a Tk window is available", False, str(e))
        return

    try:
        tab = XaiTab(nb, "ForenXAI_Cases")
        filled = [("stale text from the previous capture", None)]
        for w in (tab.txt_summary, tab.txt_shap, tab.txt_recommend):
            tab._write(w, filled)
        tab.lst_findings.insert(_tk.END, "Slowloris  133 flows")
        tab.investigator_decision.set("Escalate")
        tab.txt_investigator_comment.insert("1.0", "looks like a DoS")
        tab._quarantined = ["dos.md"]

        first = tab._run_id
        tab._results.put(("all", {"summary": {}}, first))
        second = tab._reset_panels("Waiting for the analysis to start.")

        for name, w in (("1", tab.txt_summary), ("2", tab.txt_shap),
                        ("3", tab.txt_recommend)):
            body = w.get("1.0", _tk.END)
            check(f"panel {name} no longer shows the previous capture",
                  "stale text" not in body, body[:60])
        check("the findings list is emptied",
              tab.lst_findings.size() == 0)
        check("the investigator review does not carry over",
              tab.investigator_decision.get() == "Pending"
              and not tab.txt_investigator_comment.get("1.0", _tk.END).strip())
        check("the quarantine banner is cleared", not tab._quarantined)
        check("a new run id is issued", second != first)

        # The queued result from the outgoing analysis must be dropped, not
        # painted into the panels that were just cleared.
        tab._results.put(("all", {"summary": {"lines": ["OLD CAPTURE"]}},
                          first))
        tab._poll()
        body = tab.txt_summary.get("1.0", _tk.END)
        check("a result from the previous run is not rendered",
              "OLD CAPTURE" not in body, body[:60])
        check("the queue is empty afterwards", tab._results.empty())
    finally:
        try:
            root.destroy()
        except Exception:
            pass


def test_layout():
    """Every data root resolves, in whichever layout this copy is.

    The development tree keeps models/, knowledge/ and artifacts/ at the
    root; the handoff splits them by tab. A path spelled out in one module
    instead of taken from these roots passes here and fails in the other
    copy -- which is exactly how test_panels_suite.py came to load
    features.pkl from a directory the handoff does not have.
    """
    section("R  LAYOUT  the data roots resolve in this copy")
    from services.panels_service import BUNDLE_DIR, KNOWLEDGE_DIR
    from services.model_service import ARTIFACTS_DIR, discover_models
    import fetch_knowledge as fk

    for name, path, must in (
            ("the model bundle", BUNDLE_DIR, "XGBoost.pkl"),
            ("the knowledge corpus", KNOWLEDGE_DIR, "incident_response"),
            ("the forensic artifacts", ARTIFACTS_DIR, "ForenXAI-Multiclass")):
        check(f"{name} resolves", os.path.isdir(path), path)
        check(f"{name} holds {must}",
              os.path.exists(os.path.join(path, must)), path)

    # source_guard reads every source path through fetch_knowledge, so the
    # two corpus roots have to be the same directory, not merely both valid.
    check("fetch_knowledge and panels_service agree on the corpus",
          os.path.normcase(os.path.abspath(fk.KNOWLEDGE))
          == os.path.normcase(os.path.abspath(KNOWLEDGE_DIR)),
          f"{fk.KNOWLEDGE} != {KNOWLEDGE_DIR}")

    check("the forensic tab can discover its model",
          "ForenXAI-Multiclass" in discover_models(),
          str(list(discover_models())))


def test_magnitude_check():
    """A comparison against the training distribution is verified.

    This is check 6b, and it exists because the checks it sits beside all
    passed a paragraph saying a value supplied as "typical for this feature"
    deviates from the training mean. An adjective was caught; the same claim
    written as a phrase was not. No model needed -- the rule is what is
    under test, not the prose.
    """
    section("O  MAGNITUDE  a claim about the training distribution is checked")
    from services.narration_schema import check as grounding

    attrs = [{"plain": "total header bytes in inbound packets",
              "contribution": -0.63,
              "magnitude": "typical for this feature in the training data"},
             {"plain": "destination port -- effectively which service",
              "contribution": 0.69,
              "magnitude": "1.4 standard deviations above the training mean",
              "caution": "may have learned the lab's service layout"}]

    def sev(text):
        f = [x for x in grounding(text, "prompt", [], strict_mechanism=True,
                                  attributions=attrs)[0]
             if x["check"] == "magnitude"]
        return f[0]["severity"] if f else None

    check("contradicting a supplied 'typical' is high severity",
          sev("The total header bytes in inbound packets are 56, deviating "
              "from the training mean.") == "high")
    check("agreeing with what was supplied passes",
          sev("The total header bytes in inbound packets are 56, typical for "
              "this feature.") is None)
    check("comparing a feature whose figure was withheld is medium",
          sev("The destination port was 62,636, which deviates from the "
              "training mean.") == "medium")
    check("a sentence that says typical is not a deviation claim",
          sev("Total header bytes in inbound packets, 56, is higher than the "
              "previous flow but typical for this feature.") is None)
    check("the claim is scoped to the sentence it sits in",
          sev("The destination port was 62,636. Total header bytes in "
              "inbound packets are typical.") is None)


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
    test_magnitude_check()
    test_direction_check()
    test_mechanism_and_scale()
    test_prompt_shape(sample)
    test_progress(sample)
    test_layout()

    if args.llm or args.all:
        test_narration(sample)

    if args.ui or args.all:
        test_reset_on_new_capture(sample)
        section("H  WIDGETS  the tab fills without a display error")
        try:
            import tkinter as tk
            from tkinter import ttk
            XaiTab = load_xai_tab()
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
