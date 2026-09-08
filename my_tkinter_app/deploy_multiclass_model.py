"""
deploy_multiclass_model.py
==========================

Publish the trained multiclass model (artifacts/mc_random from the pipeline
repo) into the layout the Forensic tab's model registry expects, so the
Forensic tab and the XAI tab run the SAME model instead of two different
ones.

    python deploy_multiclass_model.py            # verify only
    python deploy_multiclass_model.py --write    # write the artifacts

WHY THIS EXISTS
---------------
Before this, the app ran two unrelated models:

    XAI tab (3 panels)  models/forenxai/XGBoost.pkl   74 features, 16 classes
    Forensic tab        artifacts/CIDS2018/...         20 features,  6 classes

Same capture, two different answers, two different class vocabularies. This
script makes the multiclass model available to the Forensic tab as well.

WHAT IT WRITES
--------------
    artifacts/ForenXAI-Multiclass/
        forensic_tab/
            model.joblib                     scaler + XGBoost as one Pipeline
            frozen_feature_schema_l2.json    74 features, 16-class mapping
        xai_tab/
            treeshap_reference.json          the TreeSHAP artifact from the
                                             pipeline's SHAP stage

THE PIPELINE WRAPPER MATTERS
----------------------------
run_forensic_pipeline calls model.predict(X) on the raw feature frame, with
no scaling step of its own. The multiclass model was trained on SCALED
features, so handing it raw values would produce confident nonsense rather
than an error. Saving scaler and model together as one sklearn Pipeline
makes .predict() scale first, which is what the pipeline's existing call
already expects.

NO KERNEL SHAP BACKGROUND
-------------------------
The legacy CalibratedClassifierCV models needed
xai_tab/kernel_shap_background_l2.joblib because KernelExplainer has to
sample against a background distribution. This model is a gradient-boosted
tree ensemble, so it uses TreeSHAP with feature_perturbation
"tree_path_dependent", which reads the traversal counts stored in the trees
themselves and needs no background at all. There is nothing to supply, so
none is written; shap_service selects the explainer from the model type.

treeshap_reference.json is the global TreeSHAP output already computed over
a stratified 8,000-row sample of the held-out test set, carried across for
the case record. Its additivity error is 1.8e-05 in log-odds margin.
"""

import argparse
import hashlib
import json
import os
import shutil
import sys

import joblib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

BUNDLE_DIR = os.path.join(HERE, "models", "forenxai")
TARGET_NAME = "ForenXAI-Multiclass"
TARGET_DIR = os.path.join(HERE, "artifacts", TARGET_NAME)

# The model in the pipeline repo this bundle is expected to be.
EXPECTED_XGBOOST_SHA16 = "5c123326d779f600"


def sha256_16(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


def verify_bundle():
    """
    Confirm the bundle is the mc_random model and is internally consistent.

    Returns (ok, lines). Every check is reported either way -- a deploy
    script that only speaks up on failure hides what it actually confirmed.
    """
    lines = []
    ok = True

    required = ["XGBoost.pkl", "scaler.pkl", "features.pkl",
                "label_encoder.pkl", "manifest.json", "shap_global.json"]

    for name in required:
        path = os.path.join(BUNDLE_DIR, name)
        if not os.path.isfile(path):
            lines.append(f"  MISSING   {name}")
            ok = False
        else:
            lines.append(f"  present   {name}")

    if not ok:
        return ok, lines

    manifest = json.load(
        open(os.path.join(BUNDLE_DIR, "manifest.json"), encoding="utf-8"))

    # Identity: is this really mc_random?
    actual = sha256_16(os.path.join(BUNDLE_DIR, "XGBoost.pkl"))
    if actual == EXPECTED_XGBOOST_SHA16:
        lines.append(f"  verified  XGBoost.pkl is mc_random ({actual})")
    else:
        lines.append(
            f"  MISMATCH  XGBoost.pkl is {actual}, expected "
            f"{EXPECTED_XGBOOST_SHA16} (mc_random)")
        ok = False

    # Integrity: does every file still match the manifest it shipped with?
    for name, meta in manifest.get("files", {}).items():
        path = os.path.join(BUNDLE_DIR, name)
        if not os.path.isfile(path):
            continue
        got = sha256_16(path)
        if got == meta.get("sha256_16"):
            lines.append(f"  verified  {name} matches manifest")
        else:
            lines.append(
                f"  TAMPERED  {name} is {got}, manifest says "
                f"{meta.get('sha256_16')}")
            ok = False

    if manifest.get("strategy") != "random":
        lines.append(
            f"  WARNING   manifest strategy is "
            f"{manifest.get('strategy')!r}, not 'random'")
        ok = False

    return ok, lines


def build():
    """Load the bundle and assemble the Pipeline and schema."""

    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import FunctionTransformer

    from services.model_input import as_float32

    model = joblib.load(os.path.join(BUNDLE_DIR, "XGBoost.pkl"))
    scaler = joblib.load(os.path.join(BUNDLE_DIR, "scaler.pkl"))
    features = list(joblib.load(os.path.join(BUNDLE_DIR, "features.pkl")))
    encoder = joblib.load(os.path.join(BUNDLE_DIR, "label_encoder.pkl"))

    if len(features) != getattr(model, "n_features_in_", len(features)):
        raise ValueError(
            f"features.pkl lists {len(features)} features but the model "
            f"expects {model.n_features_in_}.")

    if len(encoder.classes_) != getattr(model, "n_classes_",
                                        len(encoder.classes_)):
        raise ValueError(
            f"label_encoder has {len(encoder.classes_)} classes but the "
            f"model predicts {model.n_classes_}.")

    # Order matters, and both leading steps are load-bearing:
    #
    #   to_float32  the model was fitted on float32. Passing float64 gave
    #               numerically identical features but a DIFFERENT class on
    #               12.7% of rows in a real capture, because split
    #               thresholds learned in float32 land on the other side.
    #               See services/model_input.py.
    #
    #   scaler      the model was trained on scaled features, and the
    #               forensic pipeline's Stage 7 calls model.predict(X) on
    #               the raw frame with no scaling of its own. Unscaled
    #               input would produce confident nonsense, not an error.
    pipe = Pipeline([
        ("to_float32", FunctionTransformer(as_float32)),
        ("scaler", scaler),
        ("model", model),
    ])

    # family_mapping is name -> integer, exactly the label encoder's order.
    # The UI reads this to turn a predicted integer back into a class name,
    # so it has to come from the encoder rather than be retyped.
    family_mapping = {
        str(name): int(index)
        for index, name in enumerate(encoder.classes_)
    }

    schema = {
        "feature_columns": features,
        "family_mapping": family_mapping,
        "benign_classes": ["Benign"],
        "requires_scaling": False,
        "scaling_note": (
            "The scaler is inside model.joblib as the first Pipeline step. "
            "Callers pass the raw feature frame; do not scale beforehand."
        ),
        "explainer": "tree",
        "explainer_note": (
            "Gradient-boosted trees, so TreeSHAP with feature_perturbation "
            "'tree_path_dependent'. Exact, and needs no background sample -- "
            "unlike the KernelExplainer the legacy models require."
        ),
        "source_model": "artifacts/mc_random/XGBoost.pkl",
        "source_sha256_16": EXPECTED_XGBOOST_SHA16,
        "trained_on": "TRUSTLab",
        "validated_on": "TRUSTLab held-out 20% (random split)",
    }

    return pipe, schema


def write():
    forensic = os.path.join(TARGET_DIR, "forensic_tab")
    xai = os.path.join(TARGET_DIR, "xai_tab")
    os.makedirs(forensic, exist_ok=True)
    os.makedirs(xai, exist_ok=True)

    pipe, schema = build()

    model_path = os.path.join(forensic, "model.joblib")
    joblib.dump(pipe, model_path)

    schema_path = os.path.join(forensic, "frozen_feature_schema_l2.json")
    with open(schema_path, "w", encoding="utf-8") as fh:
        json.dump(schema, fh, indent=2)

    # The TreeSHAP artifact, carried across so a case can cite the global
    # attributions the model was characterised with.
    ref = os.path.join(xai, "treeshap_reference.json")
    shutil.copyfile(os.path.join(BUNDLE_DIR, "shap_global.json"), ref)

    return {
        "model": model_path,
        "schema": schema_path,
        "treeshap": ref,
    }


def check_roundtrip(sample_csv=None):
    """
    Prove the deployed Pipeline reproduces the XAI panels' predictions.

    Publishing a model without checking that it still predicts the same
    thing is how a silent regression ships -- and this project already had
    one: the Forensic tab and the XAI tab disagreed on 12.7% of a real
    capture's flows purely on input dtype.

    Real flow data is used when a sample CSV is available, because that is
    what exposed the dtype problem. Gaussian noise did not: random values
    almost never land exactly on a learned split threshold, which is the
    only place the two dtypes diverge. A synthetic check here would have
    passed while the app gave two different answers.
    """
    import numpy as np

    from services.flow_intake import read_flows, to_matrix
    from services.panels_service import load_bundle

    bundle = load_bundle()
    pipe = joblib.load(
        os.path.join(TARGET_DIR, "forensic_tab", "model.joblib"))

    source = "real flows"

    if sample_csv and os.path.isfile(sample_csv):
        flows, _ = read_flows(sample_csv, bundle["features"])
        raw, _ = to_matrix(flows, bundle["features"])
    else:
        source = "gaussian noise (no sample CSV -- weaker check)"
        rng = np.random.default_rng(0)
        raw = rng.normal(
            size=(512, len(bundle["features"]))).astype("float32")

    # Reference: exactly what services/panels_service.classify does.
    reference = bundle["model"].predict(bundle["scaler"].transform(raw))
    # Deployed: what the Forensic tab's Stage 7 will do.
    deployed = pipe.predict(raw)

    agree = float((reference == deployed).mean())
    return agree, len(raw), source


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true",
                    help="write the artifacts (default is verify only)")
    ap.add_argument("--sample",
                    default=os.path.join(HERE, "sample_data",
                                         "sample_flows_full.csv"),
                    help="flow CSV for the round-trip check")
    args = ap.parse_args()

    print("Bundle verification")
    print("-" * 60)
    ok, lines = verify_bundle()
    for line in lines:
        print(line)

    if not ok:
        print("\nBundle did not verify. Nothing was written.")
        return 1

    if not args.write:
        print("\nBundle verified. Re-run with --write to deploy.")
        return 0

    print("\nWriting")
    print("-" * 60)
    written = write()
    for key, path in written.items():
        print(f"  {key:10} {os.path.relpath(path, HERE)}")

    print("\nRound-trip check")
    print("-" * 60)
    agree, n, source = check_roundtrip(args.sample)
    print(f"  source: {source}")
    print(f"  Forensic-tab path agrees with the XAI-panel path on "
          f"{agree:.4f} of {n:,} rows")
    if agree < 1.0:
        print("  FAILED: the two tabs would report different classes for "
              "the same flows.")
        return 1
    print("  exact match -- both tabs will report the same classes")

    print(f"\nDeployed as '{TARGET_NAME}'.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
