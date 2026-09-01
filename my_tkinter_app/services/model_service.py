import os
import json
import joblib


# ============================================================
# ARTIFACTS DIRECTORY
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(__file__)
)

ARTIFACTS_DIR = os.path.join(
    BASE_DIR,
    "artifacts"
)


# ============================================================
# DISCOVER AVAILABLE MODELS
# ============================================================

def discover_models():
    """
    Detect every available trained model inside:

        artifacts/
            CIDS2018/
                forensic_tab/
                    model.joblib
                    frozen_feature_schema_l2.json

            TII/
                forensic_tab/
                    model.joblib
                    frozen_feature_schema_l2.json

    Returns:
        {
            "CIDS2018": {
                "name": "CIDS2018",
                "model_path": "...",
                "schema_path": "...",
                "shap_background": "..."
            },
            ...
        }
    """

    models = {}

    if not os.path.exists(
        ARTIFACTS_DIR
    ):
        return models

    for dataset in os.listdir(
        ARTIFACTS_DIR
    ):

        dataset_dir = os.path.join(
            ARTIFACTS_DIR,
            dataset
        )

        if not os.path.isdir(
            dataset_dir
        ):
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

        if os.path.exists(
            model_path
        ):

            models[dataset] = {
                "name": dataset,
                "model_path": model_path,
                "schema_path": schema_path,
                "shap_background": shap_bg_path
            }

    return models


# ============================================================
# LOAD SELECTED MODEL
# ============================================================

def load_model(dataset_name):
    """
    Load the trained model for the selected dataset.

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
# LOAD FROZEN FEATURE SCHEMA
# ============================================================

def load_feature_schema(
    dataset_name
):
    """
    Load the frozen schema associated with
    the selected dataset.
    """

    models = discover_models()

    if dataset_name not in models:

        raise FileNotFoundError(
            f"Schema for model '{dataset_name}' "
            "was not found."
        )

    schema_path = models[
        dataset_name
    ]["schema_path"]

    if not os.path.isfile(
        schema_path
    ):

        raise FileNotFoundError(
            f"Frozen feature schema does not exist:\n"
            f"{schema_path}"
        )

    with open(
        schema_path,
        "r",
        encoding="utf-8"
    ) as f:

        return json.load(f)


# ============================================================
# EXPECTED MODEL FEATURES
# ============================================================

def get_expected_features(
    dataset_name
):
    """
    Return the frozen feature list used by the
    selected trained model.
    """

    schema = load_feature_schema(
        dataset_name
    )

    return schema[
        "feature_columns"
    ]


# ============================================================
# NEW:
# GET DATASET CLASS MAPPING
# ============================================================

def get_family_mapping(
    dataset_name
):
    """
    Return the frozen multiclass family mapping
    stored inside the selected model schema.

    Example:

        {
            "Benign": 0,
            "Botnet": 1,
            "Bruteforce": 2,
            "DoS": 3,
            "Infiltration": 4,
            "Web Attack": 5
        }

    The UI uses this mapping to convert model
    predictions such as 0, 1, 2, 3... into
    their actual classification names.

    IMPORTANT:
        The mapping comes from the frozen schema.
        It is NOT hardcoded inside the UI.
    """

    schema = load_feature_schema(
        dataset_name
    )

    mapping = schema.get(
        "family_mapping",
        {}
    )

    if not isinstance(
        mapping,
        dict
    ):

        return {}

    return mapping

def get_shap_background(dataset_name):
    """
    Return the SHAP background artifact for the
    selected dataset.
    """

    models = discover_models()

    if dataset_name not in models:
        raise FileNotFoundError(
            f"SHAP background for model '{dataset_name}' "
            "was not found."
        )

    shap_background_path = models[
        dataset_name
    ].get("shap_background")

    if not shap_background_path:
        raise FileNotFoundError(
            f"No SHAP background is configured for "
            f"'{dataset_name}'."
        )

    if not os.path.isfile(
        shap_background_path
    ):
        raise FileNotFoundError(
            "SHAP background artifact does not exist:\n"
            + shap_background_path
        )

    return shap_background_path


# ============================================================
# VALIDATE MODEL SCHEMA
# ============================================================

def validate_model_schema(
    dataset_name,
    df
):
    """
    Validate that every frozen model feature
    exists in the supplied DataFrame.

    Returns:

        expected_features,
        missing_features
    """

    expected = get_expected_features(
        dataset_name
    )

    missing = [
        feature
        for feature in expected
        if feature not in df.columns
    ]

    return expected, missing