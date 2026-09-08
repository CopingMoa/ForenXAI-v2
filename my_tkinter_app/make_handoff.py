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
    # The two models. Same XGBoost either way -- see README.
    ("models/forenxai", "models/forenxai", True),
    ("artifacts/ForenXAI-Multiclass", "artifacts/ForenXAI-Multiclass", True),

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

    # The RAG corpus.
    ("knowledge", "knowledge", True),

    # Reference renderer. Not required -- shows the expected wiring.
    ("views/xai_tab.py", "reference/xai_tab.py", False),

    # So they can prove the integration works in their tree.
    ("test_panels_suite.py", "test_panels_suite.py", False),
    ("sample_data", "sample_data", True),

    ("requirements.txt", "requirements.txt", False),
    ("handoff_docs/README.md", "README.md", False),
    ("handoff_docs/OLLAMA.md", "OLLAMA.md", False),
    ("fetch_knowledge.py", "fetch_knowledge.py", False),
    ("deploy_multiclass_model.py", "deploy_multiclass_model.py", False),
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
        pdfs = os.path.join(out, "knowledge", "_sources")
        for name in os.listdir(pdfs):
            if not name.endswith(".json"):
                os.remove(os.path.join(pdfs, name))
        print("  pruned  knowledge/_sources/*.pdf (manifest kept)")

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
    return result.returncode


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(
        os.path.dirname(HERE), "ForenXAI_UI_Handoff"))
    ap.add_argument("--no-sources", action="store_true",
                    help="skip the source PDFs (~34 MB)")
    args = ap.parse_args()

    out = os.path.abspath(args.out)
    print(f"Building {out}")
    print("-" * 60)
    build(out, include_sources=not args.no_sources)

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
