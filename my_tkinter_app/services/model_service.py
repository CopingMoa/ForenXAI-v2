import os
import joblib

from services.config import MODEL_PATH


def load_model():
    """
    Loads the trained Random Forest model from MODEL_PATH.
    Returns the model, or None if it isn't available yet.
    Never raises — a missing/broken model should not crash the app,
    it should just leave the app running in a "no model loaded" state.
    """

    if not os.path.exists(MODEL_PATH):
        print("[!] Model file not found:")
        print(MODEL_PATH)
        return None

    try:
        model = joblib.load(MODEL_PATH)
        print("[+] Random Forest model loaded successfully.")
        return model

    except Exception as e:
        print(f"[!] Error loading model: {e}")
        return None


def get_expected_features(model):
    if model is None:
        raise RuntimeError("Machine learning model is not loaded.")

    if not hasattr(model, "feature_names_in_"):
        raise RuntimeError(
            "The trained model does not contain feature_names_in_. "
            "The inference schema cannot be safely verified."
        )

    return list(model.feature_names_in_)


def validate_model_schema(model, df):
    expected_features = get_expected_features(model)

    missing_features = [
        feature
        for feature in expected_features
        if feature not in df.columns
    ]

    return expected_features, missing_features
