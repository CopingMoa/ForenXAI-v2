import os
import json

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from services.utils import calculate_sha256


# ============================================================
# SHAP AVAILABILITY
# ============================================================

try:
    import shap

    SHAP_AVAILABLE = True

except ImportError:

    SHAP_AVAILABLE = False


# ============================================================
# SHAP VALUE NORMALIZATION
# ============================================================

def normalize_shap_values(
    shap_values,
    X,
    predictions
):
    """
    Normalize SHAP output into:

        (n_samples, n_features)

    SHAP can return different shapes depending on the
    SHAP version and model output.

    Supported cases:

        Binary / single-output:
            (samples, features)

        Multiclass / multi-output:
            (samples, features, classes)

    For multiclass output, the SHAP values corresponding
    to each flow's predicted class are selected.
    """

    # --------------------------------------------------------
    # Convert to NumPy
    # --------------------------------------------------------

    values = np.asarray(
        shap_values
    )

    # --------------------------------------------------------
    # Case 1:
    #
    # Already:
    #
    #     samples × features
    # --------------------------------------------------------

    if values.ndim == 2:

        if values.shape[0] != len(X):

            raise ValueError(
                "SHAP output sample count does not match "
                "the inference DataFrame."
            )

        if values.shape[1] != len(X.columns):

            raise ValueError(
                "SHAP output feature count does not match "
                "model input feature count."
            )

        return values


    # --------------------------------------------------------
    # Case 2:
    #
    # samples × features × classes
    # --------------------------------------------------------

    if values.ndim == 3:

        n_samples = values.shape[0]
        n_features = values.shape[1]
        n_classes = values.shape[2]

        if n_samples != len(X):

            raise ValueError(
                "SHAP output sample count does not match "
                "the inference DataFrame."
            )

        if n_features != len(X.columns):

            raise ValueError(
                "SHAP output feature count does not match "
                "model input feature count."
            )

        class_indices = []

        for prediction in predictions:

            try:

                class_index = int(
                    prediction
                )

            except (
                TypeError,
                ValueError
            ):

                class_index = 0

            if (
                class_index < 0
                or class_index >= n_classes
            ):

                class_index = 0

            class_indices.append(
                class_index
            )

        normalized = np.zeros(
            (
                n_samples,
                n_features
            ),
            dtype=float
        )

        for i, class_index in enumerate(
            class_indices
        ):

            normalized[i] = values[
                i,
                :,
                class_index
            ]

        return normalized


    # --------------------------------------------------------
    # Unsupported SHAP format
    # --------------------------------------------------------

    raise ValueError(
        "Unsupported SHAP output shape: "
        f"{values.shape}"
    )


# ============================================================
# KERNEL SHAP EXPLANATION
# ============================================================

def generate_shap_explanation(
    model,
    X,
    predictions,
    case_id,
    case_dir,
    log_fn,
    shap_background
):
    """
    Generate Kernel SHAP explanations for the selected
    ForenXAI model.

    IMPORTANT:

    shap_background must contain the ACTUAL background
    data, not the path to the .joblib file.

    Expected background:

        SHAP DenseData
        or
        NumPy array

    The function explains:

        model.predict_proba(X)

    This is intentionally model-agnostic and therefore
    works with the current CalibratedClassifierCV model.
    """

    # ========================================================
    # SHAP AVAILABILITY
    # ========================================================

    if not SHAP_AVAILABLE:

        log_fn(
            "[!] SHAP is not installed. "
            "Explanation stage skipped.",
            "error"
        )

        return None, None


    # ========================================================
    # BACKGROUND VALIDATION
    # ========================================================

    if shap_background is None:

        log_fn(
            "[!] SHAP background is not available. "
            "Explanation stage skipped.",
            "error"
        )

        return None, None


    try:

        # ====================================================
        # STAGE 1 — PREPARE BACKGROUND
        # ====================================================

        log_fn(
            "[*] Preparing frozen Kernel SHAP background...",
            "info"
        )


        # ----------------------------------------------------
        # Your .joblib artifact contains:
        #
        # shap.utils._legacy.DenseData
        #
        # The actual NumPy matrix is stored in:
        #
        #     shap_background.data
        #
        # ----------------------------------------------------

        if hasattr(
            shap_background,
            "data"
        ):

            background_data = (
                shap_background.data
            )

        else:

            background_data = (
                np.asarray(
                    shap_background
                )
            )


        # ----------------------------------------------------
        # Convert to numeric NumPy matrix
        # ----------------------------------------------------

        background_data = np.asarray(
            background_data,
            dtype=float
        )


        # ====================================================
        # VALIDATE BACKGROUND DIMENSIONS
        # ====================================================

        if background_data.ndim != 2:

            raise ValueError(
                "SHAP background must be a "
                "2-dimensional matrix."
            )


        # ----------------------------------------------------
        # Number of features must match X
        # ----------------------------------------------------

        if background_data.shape[1] != len(
            X.columns
        ):

            raise ValueError(
                "SHAP background feature count "
                "does not match model input.\n\n"
                f"Background features: "
                f"{background_data.shape[1]}\n"
                f"Model features: "
                f"{len(X.columns)}"
            )


        # ----------------------------------------------------
        # Make sure background contains no NaN/Infinity
        # ----------------------------------------------------

        if not np.isfinite(
            background_data
        ).all():

            raise ValueError(
                "SHAP background contains "
                "NaN or infinite values."
            )


        log_fn(
            "[+] Frozen SHAP background loaded: "
            f"{background_data.shape[0]} samples × "
            f"{background_data.shape[1]} features.",
            "success"
        )


        # ====================================================
        # STAGE 2 — CREATE KERNEL SHAP EXPLAINER
        # ====================================================

        log_fn(
            "[*] Creating Kernel SHAP explainer...",
            "info"
        )


        # ----------------------------------------------------
        # IMPORTANT:
        #
        # DO NOT use:
        #
        #     shap.TreeExplainer(model)
        #
        # because the current CIDS2018 model is:
        #
        #     CalibratedClassifierCV
        #
        # Instead, explain the complete model through:
        #
        #     model.predict_proba
        #
        # ----------------------------------------------------

        explainer = shap.KernelExplainer(
            model.predict_proba,
            background_data
        )


        log_fn(
            "[+] Kernel SHAP explainer created.",
            "success"
        )


        # ====================================================
        # STAGE 3 — CALCULATE SHAP VALUES
        # ====================================================

        log_fn(
            "[*] Calculating SHAP values for "
            f"{len(X):,} flow(s)...",
            "info"
        )


        raw_shap_values = (
            explainer.shap_values(
                X,
                nsamples="auto"
            )
        )


        # ====================================================
        # NORMALIZE SHAP OUTPUT
        # ====================================================

        shap_values = normalize_shap_values(
            raw_shap_values,
            X,
            predictions
        )


        # ----------------------------------------------------
        # Final shape validation
        # ----------------------------------------------------

        expected_shape = (
            len(X),
            len(X.columns)
        )

        if shap_values.shape != expected_shape:

            raise ValueError(
                "Normalized SHAP output shape "
                "does not match inference data.\n\n"
                f"SHAP shape: {shap_values.shape}\n"
                f"Expected: {expected_shape}"
            )


        # ====================================================
        # STAGE 4 — PER-FLOW EXPLANATIONS
        # ====================================================

        explanation_records = []


        for i in range(
            len(X)
        ):

            feature_values = X.iloc[i]

            shap_row = shap_values[i]


            # ------------------------------------------------
            # Rank features by absolute SHAP contribution
            # ------------------------------------------------

            ranked_features = sorted(
                zip(
                    X.columns,
                    shap_row
                ),
                key=lambda item: abs(
                    float(item[1])
                ),
                reverse=True
            )


            top_features = []


            for feature, value in (
                ranked_features[:10]
            ):

                top_features.append({

                    "feature": str(
                        feature
                    ),

                    "feature_value": str(
                        feature_values[
                            feature
                        ]
                    ),

                    "shap_value": float(
                        value
                    )
                })


            explanation_records.append({

                "flow_index": int(
                    i
                ),

                "prediction": str(
                    predictions[i]
                ),

                "top_features": top_features
            })


        # ====================================================
        # STAGE 5 — SAVE SHAP JSON
        # ====================================================

        shap_path = os.path.join(
            case_dir,
            f"{case_id}_shap.json"
        )


        with open(
            shap_path,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                explanation_records,
                f,
                indent=4
            )


        shap_hash = calculate_sha256(
            shap_path
        )


        # ====================================================
        # STAGE 6 — GLOBAL SHAP IMPORTANCE
        # ====================================================

        mean_importance = np.mean(
            np.abs(
                shap_values
            ),
            axis=0
        )


        importance_df = pd.DataFrame({

            "feature": X.columns,

            "importance": mean_importance

        })


        importance_df.sort_values(
            "importance",
            ascending=True,
            inplace=True
        )


        # Show top 15 globally important features

        top_global = (
            importance_df.tail(
                15
            )
        )


        # ====================================================
        # CREATE CHART
        # ====================================================

        fig, ax = plt.subplots(
            figsize=(8, 5)
        )


        ax.barh(
            top_global["feature"],
            top_global["importance"]
        )


        ax.set_title(
            "Global SHAP Feature Importance"
        )


        ax.set_xlabel(
            "Mean |SHAP Value|"
        )


        fig.tight_layout()


        shap_plot_path = os.path.join(
            case_dir,
            f"{case_id}_shap_importance.png"
        )


        fig.savefig(
            shap_plot_path,
            dpi=150
        )


        plt.close(
            fig
        )


        # ====================================================
        # COMPLETE
        # ====================================================

        log_fn(
            "[+] SHAP explanations generated.",
            "success"
        )


        log_fn(
            "[+] SHAP explanation file: "
            + shap_path,
            "success"
        )


        log_fn(
            "[+] SHAP importance chart: "
            + shap_plot_path,
            "success"
        )


        return (
            explanation_records,
            {
                "shap_path": shap_path,
                "shap_sha256": shap_hash,
                "shap_plot_path": shap_plot_path
            }
        )


    # ========================================================
    # SHAP ERROR
    # ========================================================

    except Exception as e:

        log_fn(
            f"[!] SHAP explanation failed: {e}",
            "error"
        )

        return None, None