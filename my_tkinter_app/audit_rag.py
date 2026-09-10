"""
End-to-end RAG audit: source -> retrieval -> panel -> UI.

Walks all 16 classes and checks the chain rather than trusting it.
"""
import os
import re
import sys

# The folder this script is in. It used to be the author's desktop,
# spelled out -- which ships in the handoff and cannot resolve on
# anyone else's machine, while a tab README tells the reader to run it.
APP = os.path.dirname(os.path.abspath(__file__))
os.chdir(APP)
sys.path.insert(0, APP)

import fetch_knowledge as fk
import services.panels_service as ps

FAIL = []
FOLDERS = ["incident_response", "interpretability", "datasets", "analyst"]


def check(name, ok, detail=""):
    print(f"  {'pass' if ok else 'FAIL'}  {name}"
          + ("" if ok else f"\n          {detail}"))
    if not ok:
        FAIL.append(name)


def identity(citation):
    """
    The part of a citation naming the DOCUMENT, not a section of it.

    A playbook citing one control writes ", control SC-5," into an
    otherwise identical citation, which is correct IEEE practice for
    pointing at a section. Matching the raw string would reject that, so
    match on the identifier: the DOI where there is one, else the report
    number.
    """
    doi = re.search(r"doi:\s*(\S+?)\.?$", citation)
    if doi:
        return doi.group(1).rstrip(".")
    ident = re.search(r"(NIST [\w.\-]+|RFC \d+|arXiv:[\d.]+"
                      r"|A\d\d:\d{4}|OWASP Top 10:\d{4})", citation)
    return ident.group(1) if ident else citation[:60]


def md_files():
    for folder in FOLDERS:
        d = os.path.join("knowledge", folder)
        if not os.path.isdir(d):
            continue
        for name in sorted(os.listdir(d)):
            if name.endswith(".md"):
                yield f"{folder}/{name}", os.path.join(d, name)


# ============================================================
print("=" * 70)
print("1. SOURCES -- is every citation backed by a registered document")
print("=" * 70)

registered = {v["citation"] for v in fk.SOURCES.values()}
reg_ids = {identity(c) for c in registered}

cited = {}
quoted_keys = set()
for label, path in md_files():
    body = open(path, encoding="utf-8").read()
    for c in ps._citations_in(body):
        cited.setdefault(c.split("  [")[0], []).append(label)
    quoted_keys |= set(re.findall(r"#{1,6} From ([\w.\-]+)", body))

unregistered = {c: f for c, f in cited.items()
                if identity(c) not in reg_ids}
check(f"{len(cited)} distinct citations, all resolving to a registered "
      f"source", not unregistered,
      "\n          ".join(f"{c[:66]}... in {f}"
                          for c, f in list(unregistered.items())[:5]))

missing = sorted(k for k in quoted_keys if k not in fk.SOURCES)
check(f"{len(quoted_keys)} sources quoted, all registered", not missing,
      str(missing))

not_on_disk = sorted(k for k in quoted_keys if not fk._text_of(k))
check("every quoted source is on disk", not not_on_disk, str(not_on_disk))

# ============================================================
print()
print("=" * 70)
print("2. RETRIEVAL -- does every class resolve to its own document")
print("=" * 70)

bundle = ps.load_bundle()
classes = list(bundle["encoder"].classes_)

bad_map, missing_doc, no_cite = [], [], []
for cls in classes:
    entry = ps.KNOWLEDGE_MAP.get(cls)
    if not entry:
        bad_map.append(cls)
        continue
    path = os.path.join(ps.KNOWLEDGE_DIR, entry["doc"])
    if not os.path.isfile(path):
        missing_doc.append(cls)
        continue
    if not ps._citations_in(open(path, encoding="utf-8").read()):
        no_cite.append(cls)

check(f"all {len(classes)} classes have a KNOWLEDGE_MAP entry",
      not bad_map, str(bad_map))
check("every mapped document exists", not missing_doc, str(missing_doc))
check("every class document carries an IEEE citation", not no_cite,
      str(no_cite))

docs = [ps.KNOWLEDGE_MAP[c]["doc"] for c in classes]
check("no document is shared between classes", len(docs) == len(set(docs)))

stems = [os.path.basename(d)[:-3] for d in docs]
mismatch = [c for c, n in zip(classes, stems) if c.lower() != n]
check("filename matches its class", not mismatch, str(mismatch))

# ============================================================
print()
print("=" * 70)
print("3. RECOMMENDATIONS -- per class, what actually reaches the panel")
print("=" * 70)
print(f"  {'class':<16}{'words':>6}{'quotes':>8}{'cites':>7}{'guide':>7}"
      f"  document")

capture = {"facts": {"total_flows": 5000, "flow_engine": "python"}}


def finding_for(cls, **over):
    f = {"class": cls, "flow_count": 40, "share_of_capture": 0.10,
         "confidence_mean": 0.82, "confidence_min": 0.55,
         "confidence_max": 0.99, "low_confidence_count": 3,
         "reliability_f1": ps.LOW_CONFIDENCE_CLASSES.get(cls),
         "dominant_runner_up": None, "dominant_runner_up_share": 0.0}
    f.update(over)
    return f


for cls in classes:
    rec = ps.recommend(finding_for(cls), summary=capture)
    doc = next((x for x in rec["sections"]
                if x.get("source", "").startswith("incident_response")), None)
    words = len(doc["body"].split()) if doc else 0
    quotes = len(re.findall(r"#{1,6} From ", doc["body"])) if doc else 0
    print(f"  {cls:<16}{words:>6}{quotes:>8}{len(rec['references']):>7}"
          f"{len(rec['model_guidance']):>7}  "
          f"{os.path.basename(doc['source']) if doc else 'NONE'}")
    if not doc:
        FAIL.append(f"{cls}: no class document reached the panel")
    if not rec["references"]:
        FAIL.append(f"{cls}: no IEEE reference reached the panel")
    if rec["missing_documents"]:
        FAIL.append(f"{cls}: missing {rec['missing_documents']}")

check("every class produced a document section and references",
      not [f for f in FAIL if ": " in f])

# ============================================================
print()
print("=" * 70)
print("4. CORRECTNESS -- is the right playbook attached, and only it")
print("=" * 70)

wrong, contaminated = [], []
for cls in classes:
    rec = ps.recommend(finding_for(cls, low_confidence_count=0,
                                   reliability_f1=None))
    attached = [x.get("source") for x in rec["sections"]
                if x.get("source", "").startswith("incident_response")]
    expected = ps.KNOWLEDGE_MAP[cls]["doc"]
    if expected not in attached:
        wrong.append(f"{cls} -> {attached}")
    if [a for a in attached if a != expected]:
        contaminated.append(f"{cls}: {attached}")

check("each finding retrieves its own mapped playbook", not wrong,
      str(wrong))
check("no unrelated playbook attaches when there is no ambiguity",
      not contaminated, str(contaminated))

amb = ps.recommend(finding_for("Slowloris", dominant_runner_up="DoS",
                               dominant_runner_up_share=0.40))
srcs = [x.get("source") for x in amb["sections"]]
check("an ambiguous finding retrieves BOTH playbooks",
      "incident_response/slowloris.md" in srcs
      and "incident_response/dos.md" in srcs, str(srcs))

handwritten = [c for c in classes
               if "## From" not in open(
                   os.path.join(ps.KNOWLEDGE_DIR,
                                ps.KNOWLEDGE_MAP[c]["doc"]),
                   encoding="utf-8").read()]
if handwritten:
    print(f"  note  {len(handwritten)} class documents are hand-written with "
          f"no machine-checked")
    print(f"        quote block: {', '.join(handwritten)}. Citations are "
          f"present;")
    print(f"        the prose is the author's, so --verify cannot check it.")
else:
    check("every class document carries a machine-checked quote block", True)

# ============================================================
# Coverage. A knowledge file no finding can reach is a file nobody reads:
# it passes every citation and extract check and never appears on screen.
# interpretability/glossary.md was exactly that until it was mapped.
import glob as _glob
import itertools as _it

on_disk = {os.path.relpath(p, ps.KNOWLEDGE_DIR).replace("\\", "/")
           for p in _glob.glob(os.path.join(ps.KNOWLEDGE_DIR, "*", "*.md"))}
reached = set()
for cls in classes:
    for cap in ({"facts": {}},
                {"facts": {"total_flows": 5000, "flow_engine": "python"}}):
        for lowconf, weak, share, runner in _it.product(
                (0, 30), (False, True), (0.02, 0.5), (None, "DoS")):
            f = finding_for(cls, low_confidence_count=lowconf,
                            share_of_capture=share, dominant_runner_up=runner,
                            dominant_runner_up_share=0.4 if runner else 0.0,
                            reliability_f1=(ps.LOW_CONFIDENCE_CLASSES.get(cls)
                                            if weak else None))
            reached |= {s["source"] for s in ps.recommend(f, summary=cap)
                        ["sections"] if s.get("source")}

# features/glossary.md is read by _load_glossary() for panel 2's feature
# names, not retrieved as a document, so it is not expected here.
orphans = sorted(on_disk - reached - {"features/glossary.md"})
check(f"every knowledge document is reachable by some finding "
      f"({len(reached)}/{len(on_disk)} retrieved)", not orphans, str(orphans))

print()
print("=" * 70)
print("5. UI -- what the widget receives")
print("=" * 70)

rec = ps.recommend(finding_for("PortScan", share_of_capture=0.02,
                               low_confidence_count=30),
                   summary=capture)
rendered = "\n".join(f"{x['heading']}\n{x['body']}" for x in rec["sections"])
rendered += "\nREFERENCES\n" + "\n".join(rec["references"])

check("rendered text is non-trivial", len(rendered) > 4000,
      f"{len(rendered)} chars")
check("REFERENCES block is populated", len(rec["references"]) >= 5,
      str(len(rec["references"])))
check("model guidance is marked separately from attack guidance",
      any(x.get("kind") == "model" for x in rec["sections"]))
check("analyst actions render", any(x.get("kind") == "actions"
                                    for x in rec["sections"]))
check("no MITRE field leaks into the panel", "mitre" not in rec)
check("every section that quotes a file carries its citations",
      all(x.get("citations") for x in rec["sections"] if x.get("source")))

print()
print(f"  rendered  {len(rendered):,} chars, {len(rec['sections'])} sections,"
      f" {len(rec['references'])} references")

print()
print("=" * 70)
print("AUDIT PASSED" if not FAIL else f"{len(FAIL)} PROBLEM(S)")
for f in FAIL:
    print("  -", f)
sys.exit(len(FAIL))
