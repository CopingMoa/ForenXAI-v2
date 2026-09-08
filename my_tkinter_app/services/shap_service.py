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

def prepare_kernel_background(shap_background, n_features):
    """
    Turn the frozen background artifact into a validated numeric matrix.

    The .joblib artifact holds a shap.utils._legacy.DenseData, whose matrix
    lives in .data; older exports are plain arrays. Both are accepted, and
    both are checked, because a background with the wrong feature count
    produces attributions for the wrong columns rather than an error.
    """

    if hasattr(shap_background, "data"):
        background_data = shap_background.data
    else:
        background_data = np.asarray(shap_background)

    background_data = np.asarray(background_data, dtype=float)

    if background_data.ndim != 2:
        raise ValueError(
            "SHAP background must be a 2-dimensional matrix."
        )

    if background_data.shape[1] != n_features:
        raise ValueError(
            "SHAP background feature count does not match model input.\n\n"
            f"Background features: {background_data.shape[1]}\n"
            f"Model features: {n_features}"
        )

    if not np.isfinite(background_data).all():
        raise ValueError(
            "SHAP background contains NaN or infinite values."
        )

    return background_data


def unwrap_estimator(model):
    """
    Return (estimator, transform) for a model that may be a Pipeline.

    The multiclass model ships as Pipeline([scaler, model]) so that
    .predict() on a raw feature frame scales first. TreeSHAP has to explain
    the tree ensemble itself, on the SCALED matrix the trees were fitted
    against -- handing it the Pipeline, or raw values, gives attributions
    for a model or an input space that does not exist.

    `transform` is the function that maps the raw frame into the estimator's
    input space; it is the identity for a bare estimator.
    """

    steps = getattr(model, "named_steps", None)

    if not steps:
        return model, (lambda frame: frame)

    estimator = model.steps[-1][1]
    preprocessing = model.steps[:-1]

    def transform(frame):
        out = frame
        for _, step in preprocessing:
            out = step.transform(out)
        return out

    return estimator, transform


def generate_shap_explanation(
    model,
    X,
    predictions,
    case_id,
    case_dir,
    log_fn,
    shap_background,
    explainer_kind="kernel",
    class_names=None
):
    """
    Generate SHAP explanations for the selected ForenXAI model.

    explainer_kind selects how, and it comes from the model's frozen
    schema rather than from guesswork here:

      "tree"    TreeSHAP with feature_perturbation "tree_path_dependent".
                Exact, fast, and needs NO background sample -- the expected
                value comes from traversal counts stored in the trees. Used
                by the multiclass XGBoost model.

      "kernel"  KernelExplainer against a frozen background. The
                model-agnostic fallback, and the only option for the legacy
                CalibratedClassifierCV models, which are not tree ensembles
                TreeSHAP can read.

    shap_background must contain the ACTUAL background data, not a path.
    It is required for "kernel" and ignored for "tree".

    Units differ between the two and this matters when reading the numbers:
    Kernel SHAP here explains predict_proba, so its values are in
    probability. TreeSHAP explains the raw margin, so its values are in
    LOG-ODDS and sum to the margin plus the base value, NOT to a
    probability.
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

    # Only Kernel SHAP needs one. For a tree model a missing background is
    # the expected state, not a failure, so it must not skip the stage.
    if explainer_kind != "tree" and shap_background is None:

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

        background_data = None

        if explainer_kind == "tree":

            log_fn(
                "[*] TreeSHAP reads the expected value from the trees "
                "themselves, so no background is prepared.",
                "info"
            )

        else:

            log_fn(
                "[*] Preparing frozen Kernel SHAP background...",
                "info"
            )

            background_data = prepare_kernel_background(
                shap_background,
                len(X.columns)
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

        if explainer_kind == "tree":

            # The multiclass model is Pipeline([scaler, XGBClassifier]).
            # TreeSHAP must explain the ensemble itself, on the SCALED
            # matrix it was fitted against -- the Pipeline is not a tree
            # model, and raw values are not the space the trees split on.
            estimator, transform = unwrap_estimator(model)

            log_fn(
                f"[*] Creating TreeSHAP explainer for "
                f"{type(estimator).__name__}...",
                "info"
            )

            explainer = shap.TreeExplainer(
                estimator,
                feature_perturbation="tree_path_dependent"
            )

            explain_input = transform(X)

            log_fn(
                "[+] TreeSHAP explainer created. Values are in LOG-ODDS "
                "(margin), not probability.",
                "success"
            )

        else:

            log_fn(
                "[*] Creating Kernel SHAP explainer...",
                "info"
            )

            # The legacy models are CalibratedClassifierCV, which TreeSHAP
            # cannot read. Explain the whole estimator through its
            # predict_proba instead; values are then in probability.
            explainer = shap.KernelExplainer(
                model.predict_proba,
                background_data
            )

            explain_input = X

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


        if explainer_kind == "tree":

            # Exact: no sampling parameter, and no approximation to state.
            raw_shap_values = explainer.shap_values(
                explain_input
            )

        else:

            raw_shap_values = (
                explainer.shap_values(
                    explain_input,
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