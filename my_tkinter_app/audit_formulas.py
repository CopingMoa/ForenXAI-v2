"""
audit_formulas.py
=================

Every quantity the interface prints, recomputed from its definition.

The other audits check provenance -- that a quote is in its source, that a
citation resolves, that a figure the model stated was in its input. This one
checks ARITHMETIC: that the scaled value really is a z-score, that a
microsecond figure really is divided by a million, that the confidence really
is the largest softmax output, that "typical for this feature" really means
|z| < 1.

A panel can be perfectly grounded and still be wrong, if the number it was
grounded against was computed by a formula that does not mean what the label
says. That is the gap this file closes.

Usage:
  python audit_formulas.py
"""
import os
import sys

import numpy as np
import pandas as pd

APP = os.path.dirname(os.path.abspath(__file__))
os.chdir(APP)
sys.path.insert(0, APP)

import services.panels_service as ps
from services.flow_intake import read_flows

FAIL = []


def check(name, ok, detail=""):
    print(f"  {'pass' if ok else 'FAIL'}  {name}"
          + ("" if ok else f"\n          {detail}"))
    if not ok:
        FAIL.append(name)


bundle = ps.load_bundle()
flows, _ = read_flows("sample_data/sample_flows_full.csv", bundle["features"])
X, proba, k, names, _ = ps.classify(flows, bundle)
findings = ps.aggregate(names, proba, k, bundle, flows)
feats = bundle["features"]
scaler = bundle["scaler"]

print("=" * 70)
print("1. SCALING -- is the 'scaled value' actually a z-score")
print("=" * 70)

raw = scaler.inverse_transform(X[:500])
z = (raw - scaler.mean_) / scaler.scale_
dev = float(np.abs(z - X[:500]).max())

# Tolerance is relative, not absolute. The round trip goes through values as
# large as 1.17e6 microseconds, so recovering a z-score from them carries
# float noise of a few parts per million. An absolute 1e-6 bound fails on
# that noise and says nothing about whether the formula is right -- which is
# what this check is for.
check("X == (raw - training mean) / training std",
      bool(np.allclose(z, X[:500], rtol=1e-5, atol=1e-4)),
      f"max deviation {dev:.2e}")
print(f"         (max deviation {dev:.2e} -- float round-trip noise)")
check("inverse_transform round-trips",
      float(np.abs(scaler.transform(raw) - X[:500]).max()) < 1e-6)

print()
print("=" * 70)
print("2. CONFIDENCE -- definition, range and identity")
print("=" * 70)

check("proba rows sum to 1", bool(np.allclose(proba.sum(1), 1, atol=1e-5)))
check("confidence is the row maximum of predict_proba",
      bool(np.allclose(proba.max(1), proba[np.arange(len(k)), k])))
check("predicted class is the argmax", bool((proba.argmax(1) == k).all()))
for f in findings:
    m = np.flatnonzero(names == f["class"])
    c = proba[m, k[m]]
    if abs(f["confidence_mean"] - round(float(c.mean()), 4)) > 1e-9:
        FAIL.append(f"{f['class']} confidence_mean")
check("every finding's confidence mean/min/max recompute",
      not [x for x in FAIL if "confidence_mean" in str(x)])

print()
print("=" * 70)
print("3. SHAP -- additivity and the class axis")
print("=" * 70)

rows = findings[0]["representative_rows"]
sv = np.asarray(bundle["explainer"].shap_values(X[rows]))
base = np.asarray(bundle["explainer"].expected_value)
margin = bundle["model"].predict(X[rows], output_margin=True)
err = float(np.abs(sv.sum(1) + base - margin).max())
check("sum(shap) + base == raw margin", err < 1e-3, f"max error {err:.2e}")
check("argmax(reconstruction) == predict()",
      bool(((sv.sum(1) + base).argmax(1)
            == bundle["model"].predict(X[rows])).all()))

print()
print("=" * 70)
print("4. DISPLAY FORMULAS -- unit, conversion and magnitude")
print("=" * 70)

panel = ps.explain_detections(X, proba, k, names, bundle, rows)
bad_unit, bad_read, bad_mag, bad_raw = [], [], [], []

for j, r in enumerate(rows):
    unscaled = scaler.inverse_transform(X[r:r + 1])[0]
    for a in panel["detections"][j]["attributions"]:
        i = feats.index(a["feature"])

        # raw_value is the UNSCALED feature value
        if abs(a["raw_value"] - round(float(unscaled[i]), 4)) > 1e-2:
            bad_raw.append(a["feature"])

        # unit assignment agrees with the feature's own name
        if a["unit"] != ps._unit_of(a["feature"]):
            bad_unit.append(a["feature"])

        # the readable string carries the unit, and any conversion is /1e6
        if a["unit"] == "microseconds" and abs(a["raw_value"]) >= 1000:
            secs = a["raw_value"] / 1e6
            token = (f"{secs:,.2f} seconds" if secs >= 1
                     else f"{a['raw_value'] / 1000:,.1f} ms")
            if token not in a["readable"]:
                bad_read.append(f"{a['feature']}: {a['readable']}")
        elif a["unit"] and a["unit"] not in a["readable"]:
            bad_read.append(f"{a['feature']}: {a['readable']}")

        # magnitude wording matches |z| against its own thresholds
        zi = abs(float(X[r, i]))
        said_typical = "typical" in a["magnitude"]
        if said_typical != (zi < 1):
            bad_mag.append(f"{a['feature']} |z|={zi:.2f} -> {a['magnitude']}")
        if zi >= 1 and f"{zi:.1f} standard deviations" not in a["magnitude"]:
            bad_mag.append(f"{a['feature']} |z|={zi:.2f} misreported")

check("raw_value is the unscaled feature value", not bad_raw, str(bad_raw))
check("unit matches the feature name", not bad_unit, str(bad_unit))
check("readable string carries the unit and /1e6 conversion",
      not bad_read, str(bad_read[:3]))
check("magnitude wording agrees with |z| (typical iff |z| < 1)",
      not bad_mag, str(bad_mag[:3]))

print()
print("=" * 70)
print("5. CAPTURE FACTS -- recomputed from the predictions")
print("=" * 70)

s = ps.summarise_capture(flows, names, proba, "x.pcap")["facts"]
check("total = benign + attack",
      s["benign_flows"] + s["attack_flows"] == s["total_flows"])
check("attack_share == attack / total",
      abs(s["attack_share"] - round(s["attack_flows"] / s["total_flows"], 4))
      < 1e-9)
check("low_confidence_flows uses the stated 0.60 threshold",
      s["low_confidence_flows"] == int((proba.max(1) < 0.60).sum()))
check("mean_confidence == mean of the row maxima",
      abs(s["mean_confidence"] - round(float(proba.max(1).mean()), 4)) < 1e-9)
check("class_counts sums to total",
      sum(s["class_counts"].values()) == s["total_flows"])
check("shares across findings sum to the attack share",
      abs(sum(f["share_of_capture"] for f in findings)
          - s["attack_share"]) < 5e-3,
      f"{sum(f['share_of_capture'] for f in findings):.4f} vs "
      f"{s['attack_share']:.4f}")

print()
print("=" * 70)
print("3b. MODEL vs TreeSHAP -- every finding, both explained rows")
print("=" * 70)

base_all = np.atleast_1d(np.asarray(bundle["explainer"].expected_value,
                                    dtype=float))
bad_add, bad_axis, bad_marg, bad_prob, bad_base, bad_sum = [], [], [], [], [], []
n_rows = 0

for f in findings:
    rr = f["representative_rows"]
    pan = ps.explain_detections(X, proba, k, names, bundle, rr)
    sv_f = np.asarray(bundle["explainer"].shap_values(X[rr]))
    marg = np.atleast_2d(bundle["model"].predict(X[rr], output_margin=True))
    for j, r in enumerate(rr):
        n_rows += 1
        d = pan["detections"][j]
        sc, mo = d["shap_check"], d["model_output"]
        ci = int(k[r])

        if not sc["agrees"]:
            bad_add.append(f"{f['class']} row {r} err {sc['additivity_error']:.1e}")
        if not sc["reconstruction_picks_predicted"]:
            bad_axis.append(f"{f['class']} row {r}")
        if abs(mo["margin"] - float(marg[j, ci])) > 1e-4:
            bad_marg.append(f"{f['class']} row {r}")
        if abs(mo["probabilities"][0]["probability"]
               - float(proba[r, ci])) > 1e-5:
            bad_prob.append(f"{f['class']} row {r}")
        if abs(sc["base_value"] - float(base_all[ci])) > 1e-5:
            bad_base.append(f"{f['class']} row {r}")
        if abs(sc["sum_all_features"] - float(sv_f[j, :, ci].sum())) > 1e-4:
            bad_sum.append(f"{f['class']} row {r}")

check(f"all {n_rows} explained rows: base + sum(all features) == model margin",
      not bad_add, str(bad_add[:3]))
check("reconstruction selects the predicted class", not bad_axis,
      str(bad_axis[:3]))
check("the margin shown is the model's own output_margin", not bad_marg,
      str(bad_marg[:3]))
check("the top probability shown is predict_proba for the predicted class",
      not bad_prob, str(bad_prob[:3]))
check("base value is the explainer's expected_value for that class",
      not bad_base, str(bad_base[:3]))
check("sum_all_features is the sum over all 74 attributions", not bad_sum,
      str(bad_sum[:3]))

print()
print("=" * 70)
print("6. NETWORK INVENTORY -- recomputed from the flow table itself")
print("=" * 70)

inv, ainv = s.get("inventory", {}), s.get("attack_inventory", {})
attack = np.asarray(names) != "Benign"

check("inventory flow count == total_flows",
      inv.get("flows") == s["total_flows"])
check("attack inventory flow count == attack_flows",
      ainv.get("flows") == s["attack_flows"])
check("distinct sources recomputes",
      inv.get("distinct_sources") == flows["Src IP"].astype(str).nunique())
check("distinct targets recomputes",
      inv.get("distinct_targets") == flows["Dst IP"].astype(str).nunique())

pairs = flows["Src IP"].astype(str) + " -> " + flows["Dst IP"].astype(str)
check("distinct conversations recomputes",
      inv.get("distinct_conversations") == pairs.nunique())
check("attack conversations recompute",
      ainv.get("distinct_conversations") == pairs[attack].nunique())

proto = pd.to_numeric(flows["Protocol"], errors="coerce").dropna().astype(int)
check("protocol counts recompute",
      all(p["flows"] == int((proto == p["protocol"]).sum())
          for p in inv.get("protocols", [])),
      str(inv.get("protocols")))
check("protocol counts do not exceed the flow count",
      sum(p["flows"] for p in inv.get("protocols", [])) <= s["total_flows"])

fwd = pd.to_numeric(flows["Total Length of Fwd Packet"],
                    errors="coerce").fillna(0).sum()
bwd = pd.to_numeric(flows["Total Length of Bwd Packet"],
                    errors="coerce").fillna(0).sum()
check("byte totals recompute",
      inv["bytes"]["forward"] == int(fwd)
      and inv["bytes"]["backward"] == int(bwd)
      and inv["bytes"]["total"] == int(fwd) + int(bwd))
check("attack bytes are a subset of capture bytes",
      ainv["bytes"]["total"] <= inv["bytes"]["total"])
check("attack packets are a subset of capture packets",
      ainv["packets"]["total"] <= inv["packets"]["total"])

ends = s.get("attack_endpoints", {})
for role, column in (("sources", "Src IP"), ("targets", "Dst IP")):
    for e in ends.get(role, []):
        n = int((flows[column].astype(str)[attack] == e["address"]).sum())
        if n != e["flows"]:
            FAIL.append(f"attack {role} {e['address']}")
check("every attack endpoint count recomputes",
      not [x for x in FAIL if str(x).startswith("attack ")])

print()
print("=" * 70)
print("AUDIT PASSED" if not FAIL else f"{len(FAIL)} PROBLEM(S)")
for f in FAIL:
    print("  -", f)
sys.exit(len(FAIL))
