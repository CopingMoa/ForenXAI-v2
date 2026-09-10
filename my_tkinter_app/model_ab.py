"""Run the three UI panels through one or more local models and score them.

The pipeline's eval scores prompts in isolation. This scores the panels the
product actually renders: how often a paragraph survives its checks, what it
costs, and which checks fire.

    python model_ab.py qwen2.5:3b qwen2.5:7b
    RUNS=5 python model_ab.py qwen2.5:7b

This is how the default in llm_provider.py was chosen, and it is the thing
to re-run before changing it -- a model that scores well on the pipeline
eval can still fail a panel, because the panels carry constraints the eval
prompts do not.
"""
import os
import sys
import time
import collections

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.chdir(HERE)

from services.panels_service import build_panels          # noqa: E402
from services.llm_provider import OllamaProvider          # noqa: E402
from services import narration_service as ns              # noqa: E402

SAMPLE = os.path.join("sample_data", "sample_flows_full.csv")
if not os.path.isfile(SAMPLE):
    SAMPLE = os.path.join("sample_data", "sample_flows.csv")

RUNS = int(os.environ.get("RUNS", "3"))
PANELS = (("summary", "1 flow_summary"),
          ("shap", "2 shap_explanation"),
          ("recommend", "3 recommendations"))


def score(model):
    prov = OllamaProvider(model=model)
    ok, detail = prov.available()
    if not ok:
        print(f"  {model}: NOT AVAILABLE ({detail})")
        return None

    stat = collections.defaultdict(collections.Counter)
    checks = collections.defaultdict(collections.Counter)
    seconds = collections.defaultdict(float)

    for _ in range(RUNS):
        res = build_panels(SAMPLE, "x.pcap")
        finding = res["selected"]
        for key, label in PANELS:
            p = res[key]
            t0 = time.time()
            ns.narrate(p, prov, {"finding": finding, "shap": res.get("shap")})
            seconds[label] += time.time() - t0
            s = stat[label]
            s["runs"] += 1
            # The model's OWN paragraph surviving is the measure. A
            # deterministic fallback is the panel working, not the model.
            s["model_prose"] += 1 if (p.get("narrative")
                                      and not p.get("narration_fallback")) else 0
            s["fell_back"] += 1 if p.get("narration_fallback") else 0
            s["out"] += (p.get("narration_usage") or {}).get("output", 0)
            for f in p.get("narration_findings", []):
                checks[label][f"{f['severity']}:{f['check']}"] += 1

    print(f"\n{'=' * 70}\nMODEL: {model}   ({RUNS} runs)")
    print(f"  {'panel':<20}{'model prose':>12}{'fell back':>11}"
          f"{'out tok':>9}{'sec/run':>9}  findings")
    total_ok = total = 0
    for _, label in PANELS:
        s = stat[label]
        total_ok += s["model_prose"]
        total += s["runs"]
        f = dict(checks[label]) or "none"
        print(f"  {label:<20}{s['model_prose']:>7}/{s['runs']:<4}"
              f"{s['fell_back']:>11}{s['out'] // max(1, s['runs']):>9}"
              f"{seconds[label] / max(1, s['runs']):>9.1f}  {f}")
    print(f"  {'TOTAL':<20}{total_ok:>7}/{total:<4}"
          f"   model paragraphs kept: {total_ok / max(1, total):.0%}")
    return total_ok / max(1, total)


if __name__ == "__main__":
    for m in (sys.argv[1:] or ["qwen2.5:3b"]):
        score(m)
