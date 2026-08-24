import numpy as np
import pandas as pd

from sklearn.metrics import (
    confusion_matrix,
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    precision_recall_curve,
    auc,
    classification_report
)

from services.model_service import (
    get_expected_features
)

from services.cicflowmeter_service import (
    clean_features
)


# ============================================================
# EVALUATION DATASET
#
# IMPORTANT:
#
# This is NOT part of normal PCAP forensic ingestion.
#
# A PCAP uploaded by an investigator has unknown ground truth.
# Therefore accuracy, precision, recall, F1 and confusion
# matrix cannot legitimately be calculated from that case.
#
# This function is ONLY for a labeled research/test dataset.
# ============================================================

def run_evaluation(
    model,
    csv_path
):
    """
    Runs model evaluation against a labeled CSV.

    The CSV must contain:

        label_binary

    and every feature required by the trained model.

    Returns:

        dict containing metrics and confusion matrix.
    """

    if model is None:

        raise RuntimeError(
            "Random Forest model is not loaded."
        )

    # --------------------------------------------------------
    # Load dataset
    # --------------------------------------------------------

    df = pd.read_csv(
        csv_path,
        low_memory=False
    )

    if df.empty:

        raise ValueError(
            "The evaluation dataset is empty."
        )

    # Normalize column names so that CSV files produced
    # by CICFlowMeter/datasets with accidental whitespace
    # remain compatible.
    df.columns = [
        str(column).strip()
        for column in df.columns
    ]

    # --------------------------------------------------------
    # Ground truth
    # --------------------------------------------------------

    if "label_binary" not in df.columns:

        raise ValueError(
            "The evaluation dataset must contain "
            "'label_binary' as ground truth."
        )

    y_true = (
        df["label_binary"]
        .astype(int)
        .values
    )

    # --------------------------------------------------------
    # Model schema
    # --------------------------------------------------------

    expected_features = (
        get_expected_features(
            model
        )
    )

    missing_features = [

        feature

        for feature in expected_features

        if feature not in df.columns
    ]

    if missing_features:

        raise ValueError(
            "Evaluation dataset is missing required "
            "CICFlowMeter/model features:\n"
            + "\n".join(
                missing_features
            )
        )

    # --------------------------------------------------------
    # Feature matrix
    # --------------------------------------------------------

    X = df[
        expected_features
    ].copy()

    X = clean_features(
        X
    )

    # --------------------------------------------------------
    # Prediction
    # --------------------------------------------------------

    y_pred = (
        model
        .predict(X)
        .astype(int)
    )

    # --------------------------------------------------------
    # Prediction probabilities
    # --------------------------------------------------------

    y_probs = None

    if hasattr(
        model,
        "predict_proba"
    ):

        classes = list(
            model.classes_
        )

        if 1 in classes:

            class_index = (
                classes.index(1)
            )

            y_probs = (
                model
                .predict_proba(X)
                [:, class_index]
            )

    # --------------------------------------------------------
    # Confusion matrix
    # --------------------------------------------------------

    cm = confusion_matrix(
        y_true,
        y_pred,
        labels=[0, 1]
    )

    tn, fp, fn, tp = cm.ravel()

    # --------------------------------------------------------
    # Basic metrics
    # --------------------------------------------------------

    accuracy = accuracy_score(
        y_true,
        y_pred
    )

    precision = precision_score(
        y_true,
        y_pred,
        zero_division=0
    )

    recall = recall_score(
        y_true,
        y_pred,
        zero_division=0
    )

    f1 = f1_score(
        y_true,
        y_pred,
        zero_division=0
    )

    # --------------------------------------------------------
    # Specificity
    # --------------------------------------------------------

    specificity = (

        tn / (tn + fp)

        if (tn + fp) > 0

        else 0
    )

    # --------------------------------------------------------
    # False positive rate
    # --------------------------------------------------------

    fpr = (

        fp / (fp + tn)

        if (fp + tn) > 0

        else 0
    )

    # --------------------------------------------------------
    # False negative rate
    # --------------------------------------------------------

    fnr = (

        fn / (fn + tp)

        if (fn + tp) > 0

        else 0
    )

    # --------------------------------------------------------
    # F1 variants
    # --------------------------------------------------------

    macro_f1 = f1_score(
        y_true,
        y_pred,
        average="macro",
        zero_division=0
    )

    weighted_f1 = f1_score(
        y_true,
        y_pred,
        average="weighted",
        zero_division=0
    )

    # --------------------------------------------------------
    # AUC
    # --------------------------------------------------------

    roc_auc = 0.0
    pr_auc = 0.0

    if (
        y_probs is not None
        and len(np.unique(y_true)) == 2
    ):

        roc_auc = roc_auc_score(
            y_true,
            y_probs
        )

        precision_curve, recall_curve, _ = (
            precision_recall_curve(
                y_true,
                y_probs
            )
        )

        pr_auc = auc(
            recall_curve,
            precision_curve
        )

    # --------------------------------------------------------
    # Classification report
    # --------------------------------------------------------

    report = classification_report(
        y_true,
        y_pred,
        output_dict=True,
        zero_division=0
    )

    return {

        "confusion_matrix": cm,

        "accuracy": accuracy,

        "precision": precision,

        "recall": recall,

        "f1": f1,

        "specificity": specificity,

        "fpr": fpr,

        "fnr": fnr,

        "macro_f1": macro_f1,

        "weighted_f1": weighted_f1,

        "roc_auc": roc_auc,

        "pr_auc": pr_auc,

        "classification_report": report
    }