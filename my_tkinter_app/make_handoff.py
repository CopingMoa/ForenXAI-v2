"""
make_handoff.py — build the folder to hand to the UI team.

    python make_handoff.py                  build ../ForenXAI_UI_Handoff
    python make_handoff.py --out PATH       somewhere else
    python make_handoff.py --no-sources     skip the 34 MB of source PDFs

Copies only what the UI needs to run the model, SHAP, and the RAG panels.
Then it RUNS the test suite inside the copy, so the folder is not declared
done until it has proved itself outside the original tree. A handoff that
was never executed from its own directory is how a missing file ships.
"""

import argparse
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# (source, destination, is_directory)
PAYLOAD = [
    # DATA GOES WITH ITS TAB.
    #
    # The two serialisations of the model are not a duplicate: the forensic
    # pipeline loads the sklearn Pipeline (model.joblib, 27 MB) and the
    # panels load the plain estimator with its scaler and encoder
    # (XGBoost.pkl, 27 MB). Each tab reads one of them and never the other,
    # so splitting them by tab copies nothing twice -- it just puts each
    # where the person working on that tab will look.
    #
    # services/ stays shared. It is 350 KB of code both tabs import, and two
    # copies of a module is how they drift.
    ("artifacts/ForenXAI-Multiclass/forensic_tab",
     "forensic_tab/artifacts/ForenXAI-Multiclass/forensic_tab", True),
    ("models/forenxai", "xai_tab/models/forenxai", True),
    ("artifacts/ForenXAI-Multiclass/xai_tab",
     "xai_tab/artifacts/ForenXAI-Multiclass/xai_tab", True),

    # Everything the three panels import, and nothing else.
    ("services/__init__.py", "services/__init__.py", False),
    ("services/config.py", "services/config.py", False),
    ("services/utils.py", "services/utils.py", False),
    ("services/flow_intake.py", "services/flow_intake.py", False),
    ("services/panels_service.py", "services/panels_service.py", False),
    ("services/shap_service.py", "services/shap_service.py", False),
    ("services/model_service.py", "services/model_service.py", False),
    ("services/model_input.py", "services/model_input.py", False),
    ("services/narration_service.py", "services/narration_service.py", False),
    ("services/narration_schema.py", "services/narration_schema.py", False),
    ("services/llm_provider.py", "services/llm_provider.py", False),
    ("services/pyflow_extractor.py", "services/pyflow_extractor.py", False),
    ("services/cicflowmeter_service.py",
     "services/cicflowmeter_service.py", False),

    # Imported by the modules above, and missing until the copy's own suite
    # was run and stopped at "No module named 'services.session'". The
    # build's self-test exists for exactly this, but only reports it when
    # the build gets far enough to run -- see the --no-sources prune below,
    # which used to abort first.
    #
    # source_guard is the one that matters most: it re-verifies every quoted
    # passage against the PDF it names. A handoff without it renders the
    # panels with no check behind the quotes.
    ("services/source_guard.py", "services/source_guard.py", False),
    ("services/pipeline_service.py", "services/pipeline_service.py", False),
    ("services/session.py", "services/session.py", False),

    # The RAG corpus. Tab 2 only -- the forensic pipeline never reads it.
    ("knowledge", "xai_tab/knowledge", True),

    # One folder per tab. The heavy shared data -- knowledge/, models/,
    # artifacts/, services/ -- stays at the root and is NOT duplicated: the
    # corpus alone is 100 MB and the two tabs load the same classifier. What
    # is genuinely per-tab is the renderer and the integration notes, and
    # those are what these folders hold.
    ("views/forensic_tab.py", "forensic_tab/forensic_tab.py", False),
    ("handoff_docs/forensic_tab/README.md", "forensic_tab/README.md", False),
    ("views/xai_tab.py", "xai_tab/xai_tab.py", False),
    ("handoff_docs/xai_tab/README.md", "xai_tab/README.md", False),
    ("handoff_docs/xai_tab/RAG_INTEGRATION.md",
     "xai_tab/RAG_INTEGRATION.md", False),
    ("handoff_docs/xai_tab/UI_BACKEND_MAP.md",
     "xai_tab/UI_BACKEND_MAP.md", False),

    # So they can prove the integration works in their tree.
    ("test_panels_suite.py", "test_panels_suite.py", False),
    ("smoke_test.py", "smoke_test.py", False),
    # A fixture, not an artifact: both tabs and both suites read it, and it
    # is 1.4 MB. One copy, at the root.
    ("sample_data", "sample_data", True),

    ("requirements.txt", "requirements.txt", False),
    ("handoff_docs/README.md", "README.md", False),
    ("handoff_docs/OLLAMA.md", "OLLAMA.md", False),
    ("fetch_knowledge.py", "fetch_knowledge.py", False),
    ("deploy_multiclass_model.py", "deploy_multiclass_model.py", False),
    ("audit_rag.py", "audit_rag.py", False),
    ("model_ab.py", "model_ab.py", False),
    ("preflight.py", "preflight.py", False),
    ("export_model.py", "export_model.py", False),
    ("source_map.py", "source_map.py", False),
    ("verify_panels.py", "verify_panels.py", False),
]

SKIP_DIRS = {"__pycache__", ".git"}


def _ignore(_dir, names):
    return [n for n in names if n in SKIP_DIRS or n.endswith(".pyc")]


def build(out, include_sources=True):
    if os.path.isdir(out):
        shutil.rmtree(out)
    os.makedirs(out)

    copied = []
    for src, dst, is_dir in PAYLOAD:
        s = os.path.join(HERE, src)
        d = os.path.join(out, dst)

        if not os.path.exists(s):
            print(f"  SKIP (missing)  {src}")
            continue

        os.makedirs(os.path.dirname(d), exist_ok=True)

        if is_dir:
            shutil.copytree(s, d, ignore=_ignore)
        else:
            shutil.copy2(s, d)
        copied.append(dst)
        print(f"  copied  {dst}")

    if not include_sources:
        pdfs = os.path.join(out, "xai_tab", "knowledge", "_sources")
        # Directories as well as files. `_sources` holds an extracted-text
        # `.cache/` directory alongside the PDFs, and os.remove() on a
        # directory raises PermissionError on Windows -- which aborted the
        # whole build, so --no-sources produced nothing and the handoff
        # folder silently stayed at whatever it was last time.
        # The manifest and the extracted-text cache STAY. The cache is
        # 7.2 MB against 98 MB of PDFs and it is what source_guard verifies
        # quotes against, so keeping it is the difference between a small
        # build that still checks its quotes and a small build that cannot.
        keep = {"manifest.json", ".cache"}
        for name in os.listdir(pdfs):
            if name in keep or name.endswith(".json"):
                continue
            path = os.path.join(pdfs, name)
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
            else:
                os.remove(path)
        print("  pruned  xai_tab/knowledge/_sources/*.pdf "
              "(manifest and .cache kept)")
        print("  NOTE    quotes are verified against the extracted-text "
              "cache rather than")
        print("          the PDFs themselves. Panels report the weaker "
              "provenance. Ship the")
        print("          full build where the recipient must re-derive the "
              "text themselves.")

    # ForenXAI_Cases/ is created on import by services.config; make it here
    # so the folder does not look like it failed on first run.
    os.makedirs(os.path.join(out, "ForenXAI_Cases"), exist_ok=True)

    return copied


def verify(out):
    """Run the suite INSIDE the copy. A handoff that cannot run is not one."""
    print("\nRunning the suite inside the copy")
    print("-" * 60)
    result = subprocess.run(
        [sys.executable, "test_panels_suite.py"],
        cwd=out, capture_output=True, text=True,
    )
    tail = [ln for ln in result.stdout.splitlines() if "checks passed" in ln
            or ln.startswith("  FAIL")]
    for line in tail or result.stdout.splitlines()[-5:]:
        print("  " + line)
    if result.returncode != 0:
        print("  " + (result.stderr.splitlines() or ["(no stderr)"])[-1])

    # The self-test just wrote bytecode and an empty case folder into the
    # thing being shipped. Running it is the point; leaving its litter in
    # someone else's copy is not.
    for junk in ("__pycache__", "services/__pycache__", "ForenXAI_Cases"):
        shutil.rmtree(os.path.join(out, junk), ignore_errors=True)

    return result.returncode


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(
        os.path.dirname(HERE), "ForenXAI_UI_Handoff"))
    ap.add_argument("--no-sources", action="store_true",
                    help="skip the source PDFs (~98 MB)")
    ap.add_argument("--with-model", action="store_true",
                    help="also export the local LLM as a .gguf (4.7 GB). Off "
                         "by default: it is a registry pull for anyone with "
                         "Ollama, and only a packaged build needs the file.")
    args = ap.parse_args()

    out = os.path.abspath(args.out)
    print(f"Building {out}")
    print("-" * 60)
    build(out, include_sources=not args.no_sources)

    # Opt-in, and after the payload: the export is 4.7 GB and only a
    # packaged build needs it. Anyone with Ollama pulls the same weights
    # in one command, so shipping it by default would triple the folder
    # to save them that.
    if args.with_model:
        print(f"\nExporting the local model")
        print("-" * 60)
        sys.path.insert(0, HERE)
        from export_model import export
        export(None, os.path.join(out, "xai_tab", "models"))

    size = sum(
        os.path.getsize(os.path.join(r, f))
        for r, _, fs in os.walk(out) for f in fs
    )
    print(f"\n  total {size / 1024**2:.0f} MB")

    failures = verify(out)
    print("\nDone." if failures == 0 else
          f"\n{failures} check(s) failed in the copy -- fix before sending.")
    return failures


if __name__ == "__main__":
    sys.exit(main())
