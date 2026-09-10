"""
Are panels 1 and 2 telling the truth?

Recomputes every number independently from the CSV and the model, rather
than trusting the panel's own arithmetic. For SHAP it checks the property
that makes the attributions meaningful at all: they must reconstruct the
model's actual output.
"""
import os
import sys

import numpy as np
import pandas as pd

# The folder this script is in. It used to be the author's desktop,
# spelled out -- which ships in the handoff and cannot resolve on
# anyone else's machine, while a tab README tells the reader to run it.
APP = os.path.dirname(os.path.abspath(__file__))
os.chdir(APP)
sys.path.insert(0, APP)

import services.panels_service as ps
from services.flow_intake import read_flows

csv_path = sys.argv[1]
FAIL = []


def check(name, ok, detail=""):
    print(f"  {'pass' if ok else 'FAIL'}  {name}"
          + ("" if ok else f"\n          {detail}"))
    if not ok:
        FAIL.append(name)


bundle = ps.load_bundle()
flows, _ = read_flows(csv_path, bundle["features"])
X, proba, k, names, _ = ps.classify(flows, bundle)

print("=" * 70)
print("PANEL 1 -- every figure recomputed from the predictions")
print("=" * 70)

panel = ps.summarise_capture(flows, names, proba, "evidence.pcapng")
f = panel["facts"]

check("total_flows equals the row count",
      f["total_flows"] == len(flows), f"{f['total_flows']} vs {len(flows)}")
check("benign_flows recomputes",
      f["benign_flows"] == int((names == "Benign").sum()))
check("attack_flows recomputes",
      f["attack_flows"] == int((names != "Benign").sum()))
check("benign + attack == total",
      f["benign_flows"] + f["attack_flows"] == f["total_flows"])
check("class_counts sums to total",
      sum(f["class_counts"].values()) == f["total_flows"])
check("mean_confidence recomputes",
      abs(f["mean_confidence"] - round(float(proba.max(1).mean()), 4)) < 1e-9,
      f"{f['mean_confidence']} vs {float(proba.max(1).mean()):.4f}")
check("low_confidence_flows uses the stated 0.60 threshold",
      f["low_confidence_flows"] == int((proba.max(1) < 0.60).sum()))
check("attack_share matches the counts",
      abs(f["attack_share"]
          - round(f["attack_flows"] / f["total_flows"], 4)) < 1e-9)

# The predicted label must be the argmax of the probabilities shown.
check("names are the argmax of proba",
      bool((bundle["encoder"].inverse_transform(proba.argmax(1))
            == names).all()))
check("k indexes the predicted class",
      bool((proba.argmax(1) == k).all()))

w = f.get("capture_window")
if w:
    ts = pd.to_datetime(flows["Timestamp"], errors="coerce",
                        format="mixed", dayfirst=True)
    span = (ts.max() - ts.min()).total_seconds()
    check("capture window span recomputes from Timestamp",
          abs(w["span_seconds"] - span) < 1.5,
          f"{w['span_seconds']} vs {span}")
    print(f"        span {w['span_seconds']:.0f}s vs sum of flow "
          f"durations {f['total_flow_seconds']:.0f}s -- these are "
          f"different quantities and either may be larger")
    check("span and total_flow_seconds are reported as separate figures",
          "total_flow_seconds" in f and "span_seconds" in w)

e = f.get("endpoints", {})
if e.get("targets"):
    top = e["targets"][0]
    actual = int((flows["Dst IP"].astype(str) == top["address"]).sum())
    check("busiest target count recomputes", top["flows"] == actual,
          f"{top['flows']} vs {actual}")

print()
print("=" * 70)
print("PANEL 2 -- do the attributions reconstruct the model's output")
print("=" * 70)

findings = ps.aggregate(names, proba, k, bundle, flows)
finding = findings[0]
shap_panel = ps.explain_detections(X, proba, k, names, bundle,
                                   rows=finding["representative_rows"])

print(f"  units declared: {shap_panel['units']}")

model = bundle["model"]
scaler = bundle["scaler"]
rows = finding["representative_rows"]
# X from classify() is ALREADY SCALED -- prepare() applies the scaler before
# predict_proba. Calling scaler.transform on it again double-scales, which
# is a different input and therefore different (still exact) SHAP values.
Xs = X[rows]

import shap as shap_lib
explainer = shap_lib.TreeExplainer(
    model, feature_perturbation="tree_path_dependent")
sv = np.asarray(explainer.shap_values(Xs))
base = np.asarray(explainer.expected_value)

margin = model.predict(Xs, output_margin=True)

# ADDITIVITY: base + sum(shap) must equal the raw margin.
recon = sv.sum(axis=1) + base
err = float(np.abs(recon - margin).max())
check("attributions + base value reconstruct the model margin",
      err < 1e-3, f"max error {err:.3e}")

# The reconstruction must also pick the class the model picked.
agree = float((recon.argmax(1) == model.predict(Xs)).mean())
check("argmax(reconstruction) == predict()", agree == 1.0, f"{agree:.4f}")

# The panel must attribute for the PREDICTED class, not class 0.
det = shap_panel["detections"][0]
row = rows[0]
predicted_k = int(k[row])
panel_vals = {a["feature"]: a["contribution"] for a in det["attributions"]}
top_panel = max(panel_vals, key=lambda n: abs(panel_vals[n]))
true_vec = sv[0, :, predicted_k]
top_true = bundle["features"][int(np.argmax(np.abs(true_vec)))]
check("the panel explains the PREDICTED class",
      top_panel == top_true, f"panel={top_panel!r} truth={top_true!r}")

for a in det["attributions"][:3]:
    idx = bundle["features"].index(a["feature"])
    exact = float(sv[0, idx, predicted_k])
    ok = abs(exact - a["contribution"]) < 5e-3
    check(f"contribution matches TreeSHAP: {a['feature'][:34]}", ok,
          f"panel {a['contribution']:+.4f} vs exact {exact:+.4f}")

# Raw values shown must be the UNSCALED feature values.
a = det["attributions"][0]
idx = bundle["features"].index(a["feature"])
unscaled = scaler.inverse_transform(X[row:row + 1])[0]
check("raw_value is the UNSCALED feature value",
      abs(float(a["raw_value"]) - float(unscaled[idx])) < 1e-2,
      f"{a['raw_value']} vs {unscaled[idx]}")

check("units say log-odds, not probability",
      "log-odds" in shap_panel["units"].lower()
      and "probab" in shap_panel["units"].lower())

print()
print("=" * 70)
print("AUDIT PASSED" if not FAIL else f"{len(FAIL)} PROBLEM(S)")
for x in FAIL:
    print("  -", x)
sys.exit(len(FAIL))
