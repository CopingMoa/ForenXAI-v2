import os
import json

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from services.utils import calculate_sha256

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False


def normalize_shap_values(shap_values, X):
    """
    Normalize SHAP output into:
        shape = (n_samples, n_features)
    Supports common SHAP TreeExplainer formats.
    """

    if isinstance(shap_values, list):
        # Binary classification:
        # index 1 normally represents threat class
        if len(shap_values) > 1:
            values = shap_values[1]
        else:
            values = shap_values[0]
    else:
        values = shap_values

    values = np.asarray(values)

    # New SHAP versions may return:
    # samples x features x classes
    if values.ndim == 3:
        if values.shape[2] > 1:
            values = values[:, :, 1]
        else:
            values = values[:, :, 0]

    return values


def generate_shap_explanation(model, X, predictions, case_id, case_dir, log_fn):
    """
    log_fn(message, tag=None) is injected by the caller (the view layer)
    so this module never has to know about Tkinter widgets.
    """

    if not SHAP_AVAILABLE:
        log_fn(
            "[!] SHAP is not installed. Explanation stage skipped.",
            "error"
        )
        return None, None

    try:
        log_fn("[*] Generating SHAP explanations...", "info")

        explainer = shap.TreeExplainer(model)
        raw_shap_values = explainer.shap_values(X)
        shap_values = normalize_shap_values(raw_shap_values, X)

        if shap_values.shape[1] != len(X.columns):
            raise ValueError(
                "SHAP output feature count does not "
                "match model input feature count."
            )

        explanation_records = []

        for i in range(len(X)):
            feature_values = X.iloc[i]
            shap_row = shap_values[i]

            ranked_features = sorted(
                zip(X.columns, shap_row),
                key=lambda x: abs(float(x[1])),
                reverse=True
            )

            top_features = []

            for feature, value in ranked_features[:10]:
                top_features.append({
                    "feature": str(feature),
                    "feature_value": str(feature_values[feature]),
                    "shap_value": float(value)
                })

            explanation_records.append({
                "flow_index": int(i),
                "prediction": str(predictions[i]),
                "top_features": top_features
            })

        shap_path = os.path.join(case_dir, f"{case_id}_shap.json")

        with open(shap_path, "w", encoding="utf-8") as f:
            json.dump(explanation_records, f, indent=4)

        shap_hash = calculate_sha256(shap_path)

        # Create global SHAP importance chart
        mean_importance = np.mean(np.abs(shap_values), axis=0)

        importance_df = pd.DataFrame({
            "feature": X.columns,
            "importance": mean_importance
        })

        importance_df.sort_values("importance", ascending=True, inplace=True)
        top_global = importance_df.tail(15)

        fig, ax = plt.subplots(figsize=(8, 5))
        ax.barh(top_global["feature"], top_global["importance"])
        ax.set_title("Global SHAP Feature Importance")
        ax.set_xlabel("Mean |SHAP Value|")
        fig.tight_layout()

        shap_plot_path = os.path.join(case_dir, f"{case_id}_shap_importance.png")
        fig.savefig(shap_plot_path, dpi=150)
        plt.close(fig)

        log_fn("[+] SHAP explanations generated.", "success")

        return explanation_records, {
            "shap_path": shap_path,
            "shap_sha256": shap_hash,
            "shap_plot_path": shap_plot_path
        }

    except Exception as e:
        log_fn(f"[!] SHAP explanation failed: {e}", "error")
        return None, None
