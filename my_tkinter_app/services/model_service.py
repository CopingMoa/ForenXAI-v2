import os
import json
import joblib
import numpy as np

def get_shap_background(dataset_name):
    """
    Load the frozen Kernel SHAP background dataset
    for the selected model.

    Returns:
        numpy.ndarray with shape:
            (background_samples, model_features)

        or None for a model that uses TreeSHAP, which needs no background.

    A tree model returning None here is a correct answer, not a degraded
    one: with feature_perturbation "tree_path_dependent" the expected value
    comes from the traversal counts already stored in the trees, so there is
    no background distribution to supply. Only KernelExplainer needs one.
    """

    models = discover_models()

    if dataset_name not in models:
        raise FileNotFoundError(
            f"Model '{dataset_name}' was not found."
        )

    if get_explainer_kind(dataset_name) == "tree":
        return None

    background_path = models[
        dataset_name
    ]["shap_background"]

    if not os.path.isfile(
        background_path
    ):
        raise FileNotFoundError(
            "Frozen SHAP background file was not found:\n"
            + background_path
        )

    background = joblib.load(
        background_path
    )

    # Your artifact is a SHAP DenseData object.
    # Extract the actual NumPy matrix.
    if hasattr(
        background,
        "data"
    ):
        background = background.data

    background = np.asarray(
        background,
        dtype=float
    )

    if background.ndim != 2:
        raise ValueError(
            "Frozen SHAP background must be a "
            "2-dimensional feature matrix."
        )

    return background
    
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


# ============================================================
# BENIGN CLASS IDENTIFICATION
# ============================================================

def get_benign_class_ids(
    dataset_name
):
    """
    Return the set of predicted integers that mean "not an attack".

    This has to be read from the schema, never assumed from the integer
    value. The pipeline used to count anything in [1, 2, 3, 4, 5] as
    malicious, which happened to be right for the legacy models because
    their family_mapping puts Benign at 0. It is WRONG for the multiclass
    model, whose classes are alphabetical:

        API = 0, Benign = 1, Bruteforce = 2, ... WebBased = 15

    Under the old rule that model would have reported every Benign flow as
    a threat, every API flow as benign, and everything from DNS (6) upward
    as benign -- confident, inverted, and with no error raised.

    Returns a set of ints. Empty means the schema declares no benign class,
    which callers must treat as "cannot separate", not as "none are benign".
    """

    schema = load_feature_schema(
        dataset_name
    )

    mapping = get_family_mapping(
        dataset_name
    )

    if not mapping:
        return set()

    declared = schema.get(
        "benign_classes"
    )

    if not declared:
        # No explicit declaration: fall back to matching on the name. Every
        # schema in this project spells it "Benign".
        declared = [
            name
            for name in mapping
            if str(name).strip().lower() == "benign"
        ]

    return {
        int(mapping[name])
        for name in declared
        if name in mapping
    }


def get_class_names(
    dataset_name
):
    """
    Return predicted integer -> class name, from the frozen schema.

    The report and the UI both need to print a name rather than an index,
    and the mapping belongs to the model, not to the widget.
    """

    mapping = get_family_mapping(
        dataset_name
    )

    return {
        int(index): str(name)
        for name, index in mapping.items()
    }


def get_explainer_kind(
    dataset_name
):
    """
    Which SHAP explainer this model needs: "tree" or "kernel".

    Tree ensembles get TreeSHAP -- exact, fast, and with
    feature_perturbation "tree_path_dependent" it reads the traversal
    counts stored in the trees, so it needs no background sample.
    KernelExplainer is the model-agnostic fallback the legacy
    CalibratedClassifierCV models require, and it does need a background.

    Declared in the schema so the choice is recorded with the model rather
    than inferred at run time from whatever object happened to load.
    """

    try:
        schema = load_feature_schema(
            dataset_name
        )
    except FileNotFoundError:
        return "kernel"

    kind = str(
        schema.get("explainer", "kernel")
    ).strip().lower()

    return kind if kind in ("tree", "kernel") else "kernel"


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