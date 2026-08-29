import os
import json
import joblib

# ============================================================
# CHANGED:
# Removed MODEL_PATH import.
# We now detect every trained model inside /artifacts.
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
ARTIFACTS_DIR = os.path.join(BASE_DIR, "artifacts")


# ============================================================
# NEW:
# Scan available trained models
# ============================================================

def discover_models():
    """
    Detects every available model inside:

        artifacts/
            CIDS2018/
            TII/
            Combined/   (Brian later)

    Returns:
        {
            "CIDS2018": {...},
            "TII": {...}
        }
    """

    models = {}

    if not os.path.exists(ARTIFACTS_DIR):
        return models

    for dataset in os.listdir(ARTIFACTS_DIR):

        dataset_dir = os.path.join(
            ARTIFACTS_DIR,
            dataset
        )

        if not os.path.isdir(dataset_dir):
            continue

        forensic_dir = os.path.join(
            dataset_dir,
            "forensic_tab"
        )

        xai_dir = os.path.join(
            dataset_dir,
            "xai_tab"
        )

        model_path = os.path.join(
            forensic_dir,
            "model.joblib"
        )

        schema_path = os.path.join(
            forensic_dir,
            "frozen_feature_schema_l2.json"
        )

        shap_bg_path = os.path.join(
            xai_dir,
            "kernel_shap_background_l2.joblib"
        )

        if os.path.exists(model_path):

            models[dataset] = {
                "name": dataset,
                "model_path": model_path,
                "schema_path": schema_path,
                "shap_background": shap_bg_path
            }

    return models


# ============================================================
# NEW:
# Load a selected model
# ============================================================

def load_model(dataset_name):
    """
    Example:

        load_model("CIDS2018")
        load_model("TII")
    """

    models = discover_models()

    if dataset_name not in models:
        raise FileNotFoundError(
            f"Model '{dataset_name}' was not found."
        )

    model = joblib.load(
        models[dataset_name]["model_path"]
    )

    return model


# ============================================================
# NEW:
# Load frozen schema JSON
# ============================================================

def load_feature_schema(dataset_name):

    models = discover_models()

    schema_path = models[dataset_name]["schema_path"]

    with open(schema_path, "r") as f:
        return json.load(f)


# ============================================================
# CHANGED:
# Uses Dorothy's frozen schema instead of feature_names_in_
# ============================================================

def get_expected_features(dataset_name):

    schema = load_feature_schema(dataset_name)

    return schema["feature_columns"]


# ============================================================
# CHANGED:
# Validation now depends on selected dataset
# ============================================================

def validate_model_schema(dataset_name, df):

    expected = get_expected_features(dataset_name)

    missing = [
        f for f in expected
        if f not in df.columns
    ]

    return expected, missing