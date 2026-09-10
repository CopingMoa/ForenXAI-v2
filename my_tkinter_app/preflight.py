"""
preflight.py -- run this before sending the handoff to anyone.

    python preflight.py                 check ../ForenXAI_UI_Handoff
    python preflight.py --out PATH      check a build somewhere else

make_handoff.py runs the panel suite inside the copy, which proves the code
imports and the panels build. It does not prove the things that go wrong
when a folder is zipped, uploaded, downloaded and unzipped by someone else:
a corpus that verifies against nothing because the cache was pruned, a
model file that never made it, a document whose quotes have drifted since
the corpus was written.

Every check here failed at least once during development. That is the bar
for being in this file -- not "might be nice to confirm".
"""
import argparse
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FAIL = []
WARN = []


def check(name, ok, detail=""):
    print(f"  {'pass' if ok else 'FAIL'}  {name}")
    if not ok:
        FAIL.append(name)
        if detail:
            print(f"        {detail}")


def warn(name, ok, detail=""):
    if not ok:
        WARN.append(name)
        print(f"  warn  {name}")
        if detail:
            print(f"        {detail}")


def section(title):
    print(f"\n{title}\n{'-' * len(title)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(
        os.path.dirname(HERE), "ForenXAI_UI_Handoff"))
    args = ap.parse_args()
    out = os.path.abspath(args.out)

    # This script imports from the payload and runs two suites inside it.
    # Both write bytecode, into the very folder section D then checks for
    # bytecode. Judging a build on litter the check itself dropped is worse
    # than not checking: it fails a clean build and teaches you to ignore
    # the result. So nothing writes any.
    sys.dont_write_bytecode = True
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

    print(f"Checking {out}")
    if not os.path.isdir(out):
        print("  FAIL  the folder does not exist -- run make_handoff.py first")
        return 1

    # ---------------------------------------------------------------
    section("A  PAYLOAD  each tab has the files it loads")
    for rel in (
            "forensic_tab/forensic_tab.py",
            "forensic_tab/README.md",
            "forensic_tab/artifacts/ForenXAI-Multiclass/forensic_tab/model.joblib",
            "forensic_tab/artifacts/ForenXAI-Multiclass/forensic_tab/"
            "frozen_feature_schema_l2.json",
            "xai_tab/xai_tab.py",
            "xai_tab/README.md",
            "xai_tab/RAG_INTEGRATION.md",
            "xai_tab/models/forenxai/XGBoost.pkl",
            "xai_tab/models/forenxai/manifest.json",
            "xai_tab/knowledge/incident_response",
            "xai_tab/knowledge/_sources/manifest.json",
            "services/panels_service.py",
            "services/source_guard.py",
            "smoke_test.py",
            "requirements.txt",
            "README.md"):
        check(rel, os.path.exists(os.path.join(out, rel)))

    # ---------------------------------------------------------------
    section("B  CORPUS  every class maps to a document that is on disk")
    sys.path.insert(0, out)
    cwd = os.getcwd()
    os.chdir(out)
    try:
        for mod in [m for m in list(sys.modules)
                    if m.startswith(("services", "fetch_knowledge"))]:
            del sys.modules[mod]
        from services.panels_service import (KNOWLEDGE_MAP, KNOWLEDGE_DIR,
                                             bundle_available)
        import fetch_knowledge as fk

        check("all 16 classes are mapped", len(KNOWLEDGE_MAP) == 16,
              f"{len(KNOWLEDGE_MAP)} entries")
        missing = [e["doc"] for e in KNOWLEDGE_MAP.values()
                   if not os.path.isfile(
                       os.path.join(KNOWLEDGE_DIR, e["doc"]))]
        check("every mapped document is present", not missing, str(missing[:4]))

        # The corpus two modules disagreeing about is the failure that
        # renders panels with no check behind the quotes.
        check("fetch_knowledge and panels_service agree on the corpus",
              os.path.normcase(os.path.abspath(fk.KNOWLEDGE))
              == os.path.normcase(os.path.abspath(KNOWLEDGE_DIR)),
              f"{fk.KNOWLEDGE} != {KNOWLEDGE_DIR}")

        ok, detail = bundle_available()
        check("the model bundle loads and its manifest verifies", ok, detail)

        # ------------------------------------------------------------
        section("C  SOURCES  quotes verify, and against what")
        cache = os.path.join(KNOWLEDGE_DIR, "_sources", ".cache")
        pdfs = [f for f in os.listdir(os.path.join(KNOWLEDGE_DIR, "_sources"))
                if f.lower().endswith(".pdf")]
        has_cache = os.path.isdir(cache) and os.listdir(cache)
        check("the extracted-text cache shipped", bool(has_cache),
              "without it every quote fails and every document is quarantined")
        warn("the source PDFs shipped", bool(pdfs),
             "a --no-sources build verifies against the cache only; the "
             "recipient cannot re-derive a quote themselves")

        from services.panels_service import build_panels
        sample = os.path.join(out, "sample_data", "sample_flows_full.csv")
        if not os.path.isfile(sample):
            sample = os.path.join(out, "sample_data", "sample_flows.csv")
        res = build_panels(sample, "preflight.pcap")
        check("a capture analyses without narration", "error" not in res,
              str(res.get("error"))[:120])

        rec = res.get("recommend") or {}
        check("no retrieved document is quarantined",
              not rec.get("unverified_documents"),
              str(rec.get("unverified_documents"))[:160])
        check("no mapped document is missing",
              not rec.get("missing_documents"),
              str(rec.get("missing_documents"))[:160])
        check("panel 3 retrieved something", bool(rec.get("sections")))
        check("every reference marker resolves",
              all(r.get("citation") for r in rec.get("reference_map") or []))

        weak = [s["source"] for s in rec.get("sections") or []
                if s.get("verified_against") == "cache"]
        warn("every quote verified against its PDF, not the cache", not weak,
             f"{len(weak)} section(s) fell back to the cache")
    finally:
        os.chdir(cwd)

    # ---------------------------------------------------------------
    # Before section D, because running the suites inside the copy creates
    # bytecode there -- this script must not fail the build for its own
    # side effect, and must not leave that side effect behind either.
    section("D  HYGIENE  nothing of ours that should not travel")
    for junk in ("__pycache__", "ForenXAI_Cases", ".git"):
        check(f"no {junk}/ in the payload",
              not os.path.exists(os.path.join(out, junk)))

    # ---------------------------------------------------------------
    section("E  SELF-TEST  the copy proves itself in its own directory")
    for script in ("smoke_test.py", "test_panels_suite.py"):
        r = subprocess.run([sys.executable, script], cwd=out,
                           capture_output=True, text=True)
        line = next((l for l in r.stdout.splitlines()
                     if "checks passed" in l or "checks failed" in l), "")
        check(f"{script}: {line.strip() or 'no result line'}",
              r.returncode == 0,
              (r.stderr.splitlines() or [""])[-1][:160])

    # A case workspace is written by the suites regardless; remove it so the
    # folder is exactly what make_handoff.py built.
    shutil.rmtree(os.path.join(out, "ForenXAI_Cases"), ignore_errors=True)

    size_mb = sum(os.path.getsize(os.path.join(r, f))
                  for r, _, fs in os.walk(out) for f in fs) // (1024 * 1024)
    print(f"\n  payload {size_mb} MB")

    # ---------------------------------------------------------------
    print()
    if FAIL:
        print(f"{len(FAIL)} check(s) FAILED -- do not send this build.")
        for f in FAIL:
            print(f"  - {f}")
        return 1
    if WARN:
        print(f"Ready to send, with {len(WARN)} thing(s) to say out loud:")
        for w in WARN:
            print(f"  - {w}")
    else:
        print("Ready to send.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
