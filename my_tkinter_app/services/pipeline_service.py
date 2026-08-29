import os
import json
from datetime import datetime

import pandas as pd

from services.utils import (
    calculate_sha256,
    safe_filename,
    utc_timestamp,
)

from services.model_service import (
    validate_model_schema,
)

from services.cicflowmeter_service import (
    extract_flows_from_pcap,
    clean_features,
)

from services.shap_service import (
    generate_shap_explanation,
)


# ============================================================
# INTERNAL CSV ARTIFACT
# ============================================================

def save_internal_csv(
    df,
    case_dir,
    case_id
):
    """
    Save the normalized CICFlowMeter DataFrame as the
    internal forensic CSV artifact.

    This replaces the old Zeek-generated CSV artifact.
    """

    csv_path = os.path.join(
        case_dir,
        f"{case_id}_cicflowmeter_features.csv"
    )

    df.to_csv(
        csv_path,
        index=False
    )

    csv_hash = calculate_sha256(
        csv_path
    )

    return csv_path, csv_hash


# ============================================================
# PREDICTION ARTIFACT
# ============================================================

def save_prediction_results(
    X,
    predictions,
    threat_probabilities,
    case_dir,
    case_id
):
    records = []

    for i, prediction in enumerate(predictions):

        threat_probability = None

        if threat_probabilities is not None:
            threat_probability = float(
                threat_probabilities[i]
            )

        records.append({
            "flow_index": int(i),
            "ai_prediction": str(prediction),
            "threat_probability": threat_probability
        })

    prediction_path = os.path.join(
        case_dir,
        f"{case_id}_predictions.json"
    )

    with open(
        prediction_path,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            records,
            f,
            indent=4
        )

    prediction_hash = calculate_sha256(
        prediction_path
    )

    return prediction_path, prediction_hash


# ============================================================
# FORENSIC REPORT
# ============================================================

def generate_forensic_report(
    case_dir,
    case_id,
    pcap_path,
    pcap_sha256,
    csv_path,
    csv_sha256,
    prediction_path,
    prediction_sha256,
    shap_path,
    shap_sha256,
    total_flows,
    benign_flows,
    threat_flows,
    model_name
):
    """
    Generate the initial forensic case report.

    The report now explicitly records CICFlowMeter v4 and
    the selected ML model/dataset.
    """

    report = {
        "case_information": {
            "case_id": case_id,
            "analysis_timestamp_utc": utc_timestamp(),
            "pcap_filename": safe_filename(
                pcap_path
            ),
            "pcap_path": pcap_path,
            "pcap_sha256": pcap_sha256
        },

        "analysis_configuration": {
            "model_dataset": model_name,
            "flow_extractor": "CICFlowMeter v4"
        },

        "analysis_pipeline": [
            "PCAP / PCAPNG",
            "SHA-256 Integrity Check",
            "CICFlowMeter v4 Feature Extraction",
            "CICFlowMeter Flow CSV / DataFrame Generation",
            "Feature Name Normalization",
            "Schema Validation",
            "Data Cleaning",
            "Required Feature Selection",
            "ML Model Prediction",
            "SHAP Explanation",
            "Human Investigator Review",
            "Forensic Report and Audit Log"
        ],

        "artifacts": {
            "generated_csv": {
                "path": csv_path,
                "sha256": csv_sha256
            },

            "predictions": {
                "path": prediction_path,
                "sha256": prediction_sha256
            },

            "shap_explanation": {
                "path": shap_path,
                "sha256": shap_sha256
            }
        },

        "ai_results": {
            "total_flows": total_flows,
            "benign_flows": benign_flows,
            "threat_flows": threat_flows,

            "note": (
                "AI predictions are analytical findings "
                "and do not constitute confirmed ground truth."
            )
        },

        "human_review": {
            "decision": "Pending",
            "comment": "",
            "review_timestamp": None
        }
    }

    report_path = os.path.join(
        case_dir,
        f"{case_id}_forensic_report.json"
    )

    with open(
        report_path,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            report,
            f,
            indent=4
        )

    report_hash = calculate_sha256(
        report_path
    )

    return report_path, report_hash


# ============================================================
# MAIN FORENSIC PIPELINE
# ============================================================

def run_forensic_pipeline(
    pcap_path,
    model,
    model_name,
    case_output_dir,
    log_fn,
    on_metrics_ready=None
):
    """
    Full forensic pipeline:

        PCAP
          ->
        SHA-256
          ->
        CICFlowMeter v4
          ->
        Flow CSV
          ->
        DataFrame
          ->
        Feature normalization
          ->
        Frozen model schema
          ->
        ML prediction
          ->
        SHAP
          ->
        Forensic report

    Parameters
    ----------
    pcap_path:
        Path to .pcap or .pcapng evidence.

    model:
        Loaded sklearn-compatible ML model.

    model_name:
        Name of the selected model artifact, e.g.
        "CIDS2018" or "TII".

    case_output_dir:
        Root directory where forensic cases are created.

    log_fn:
        GUI logging callback.

    on_metrics_ready:
        Optional callback receiving:
            total_flows,
            benign_flows,
            threat_flows

    Returns
    -------
    current_case, shap_results
    """

    if model is None:
        raise RuntimeError(
            "Machine learning model is not loaded."
        )

    if not model_name:
        raise RuntimeError(
            "No ML model dataset has been selected."
        )

    case_id = datetime.now().strftime(
        "CASE_%Y%m%d_%H%M%S_%f"
    )

    case_dir = os.path.join(
        case_output_dir,
        case_id
    )

    os.makedirs(
        case_dir,
        exist_ok=True
    )

    current_case = {
        "case_id": case_id,

        "pcap_path": pcap_path,
        "pcap_sha256": None,

        "model_dataset": model_name,
        "flow_extractor": "CICFlowMeter v4",

        "generated_csv_path": None,
        "generated_csv_sha256": None,

        "prediction_path": None,
        "prediction_sha256": None,

        "shap_path": None,
        "shap_sha256": None,

        "report_path": None,
        "report_sha256": None,

        "total_flows": 0,
        "benign_flows": 0,
        "threat_flows": 0,

        "investigator_decision": "Pending",
        "investigator_comment": "",
        "review_timestamp": None
    }

    # ========================================================
    # STAGE 1 — INTEGRITY CHECK
    # ========================================================

    log_fn(
        "[Stage 1/9] Calculating SHA-256 evidence hash...",
        "info"
    )

    pcap_sha256 = calculate_sha256(
        pcap_path
    )

    current_case["pcap_sha256"] = (
        pcap_sha256
    )

    log_fn(
        f"[+] PCAP SHA-256: {pcap_sha256}",
        "success"
    )

    if os.path.getsize(
        pcap_path
    ) == 0:

        raise ValueError(
            "The uploaded PCAP file is empty (0 bytes)."
        )

    # ========================================================
    # STAGE 2 — CICFLOWMETER v4 EXTRACTION
    # ========================================================

    log_fn(
        "[Stage 2/9] Running CICFlowMeter v4 feature extraction...",
        "info"
    )

    log_fn(
        f"[+] Selected ML dataset: {model_name}",
        "info"
    )

    extracted_df, cicflowmeter_csv = (
        extract_flows_from_pcap(
            pcap_path=pcap_path,
            case_dir=case_dir,
            log_fn=log_fn
        )
    )

    if extracted_df.empty:
        raise ValueError(
            "CICFlowMeter did not extract any network flows."
        )

    log_fn(
        f"[+] CICFlowMeter extracted "
        f"{len(extracted_df):,} flow(s).",
        "success"
    )

    # ========================================================
    # STAGE 3 — INTERNAL DATAFRAME / CSV
    # ========================================================

    log_fn(
        "[Stage 3/9] Preparing CICFlowMeter DataFrame...",
        "info"
    )

    cleaned_df = clean_features(
        extracted_df
    )

    csv_path, csv_hash = save_internal_csv(
        cleaned_df,
        case_dir,
        case_id
    )

    current_case["generated_csv_path"] = csv_path
    current_case["generated_csv_sha256"] = csv_hash

    log_fn(
        f"[+] Internal CSV generated: {csv_path}",
        "success"
    )

    log_fn(
        f"[+] Internal CSV SHA-256: {csv_hash}",
        "info"
    )


    # ========================================================
    # STAGE 4 — SCHEMA VALIDATION
    # ========================================================

    log_fn(
        "[Stage 4/9] Validating selected model feature schema...",
        "info"
    )

    expected_features, missing_features = (
        validate_model_schema(
            model_name,
            cleaned_df
        )
    )

    if missing_features:

        raise ValueError(
            f"The selected {model_name} model requires "
            "features that were not produced by "
            "CICFlowMeter:\n\n"
            + "\n".join(
                missing_features
            )
            + "\n\n"
            "The ML model will NOT be executed because "
            "the feature schema cannot be safely satisfied."
        )

    log_fn(
        f"[+] {model_name} model schema validated successfully.",
        "success"
    )


    # ========================================================
    # STAGE 5 — DATA CLEANING
    # ========================================================

    log_fn(
        "[Stage 5/9] Verifying cleaned feature data...",
        "info"
    )

    # clean_features() has already been executed before
    # schema validation. Keep cleaned_df as the canonical
    # DataFrame from this point forward.

    
    # ========================================================
    # STAGE 6 — REQUIRED FEATURE SELECTION
    # ========================================================

    log_fn(
        "[Stage 6/9] Selecting frozen model features...",
        "info"
    )

    X = cleaned_df[
        expected_features
    ].copy()

    non_numeric_columns = [
        column
        for column in X.columns
        if not pd.api.types.is_numeric_dtype(
            X[column]
        )
    ]

    if non_numeric_columns:

        raise ValueError(
            "Non-numeric features remain after "
            "CICFlowMeter data cleaning:\n"
            + "\n".join(
                non_numeric_columns
            )
        )

    # --------------------------------------------------------
    # Final NaN / infinity safety check
    # --------------------------------------------------------

    if X.isna().any().any():

        nan_columns = list(
            X.columns[
                X.isna().any()
            ]
        )

        raise ValueError(
            "NaN values remain in required model features:\n"
            + "\n".join(
                nan_columns
            )
        )

    if not X.map(
        lambda value: pd.api.types.is_number(value)
    ).all().all():

        raise ValueError(
            "One or more required model features "
            "contain non-numeric values."
        )

    log_fn(
        f"[+] Selected {len(X.columns)} "
        "model features.",
        "success"
    )

    log_fn(
        "[+] Feature order matches frozen model schema.",
        "success"
    )

    # ========================================================
    # STAGE 7 — ML PREDICTION
    # ========================================================

    log_fn(
        f"[Stage 7/9] Running {model_name} ML inference...",
        "info"
    )

    predictions = model.predict(
        X
    )

    threat_probabilities = None

    if hasattr(
        model,
        "predict_proba"
    ):

        probabilities = model.predict_proba(
            X
        )

        classes = list(
            model.classes_
        )

        if 1 in classes:

            threat_class_index = (
                classes.index(1)
            )

            threat_probabilities = (
                probabilities[
                    :,
                    threat_class_index
                ]
            )

    total_flows = len(
        predictions
    )

    # --------------------------------------------------------
    # Current project convention:
    # class 0 = benign
    # class > 0 = threat/attack family
    # --------------------------------------------------------

    malicious_count = sum(
        1
        for prediction in predictions
        if prediction in [
            1,
            2,
            3,
            4,
            5,
            True,
            "Attack",
            "attack"
        ]
    )

    benign_count = (
        total_flows
        - malicious_count
    )

    current_case[
        "total_flows"
    ] = total_flows

    current_case[
        "benign_flows"
    ] = benign_count

    current_case[
        "threat_flows"
    ] = malicious_count

    prediction_path, prediction_hash = (
        save_prediction_results(
            X,
            predictions,
            threat_probabilities,
            case_dir,
            case_id
        )
    )

    current_case[
        "prediction_path"
    ] = prediction_path

    current_case[
        "prediction_sha256"
    ] = prediction_hash

    if on_metrics_ready:

        on_metrics_ready(
            total_flows,
            benign_count,
            malicious_count
        )

    log_fn(
        f"[+] Predictions generated for "
        f"{total_flows:,} flow(s).",
        "success"
    )

    log_fn(
        f"[+] Benign findings: {benign_count:,}",
        "info"
    )

    log_fn(
        f"[+] Threat findings: {malicious_count:,}",
        "error"
        if malicious_count > 0
        else "success"
    )

    # ========================================================
    # STAGE 8 — SHAP
    # ========================================================

    log_fn(
        "[Stage 8/9] Generating explainable AI output...",
        "info"
    )

    shap_results, shap_metadata = (
        generate_shap_explanation(
            model,
            X,
            predictions,
            case_id,
            case_dir,
            log_fn
        )
    )

    if shap_metadata:

        current_case[
            "shap_path"
        ] = shap_metadata[
            "shap_path"
        ]

        current_case[
            "shap_sha256"
        ] = shap_metadata[
            "shap_sha256"
        ]

    # ========================================================
    # STAGE 9 — INITIAL FORENSIC REPORT
    # ========================================================

    log_fn(
        "[Stage 9/9] Generating forensic case report...",
        "info"
    )

    report_path, report_hash = (
        generate_forensic_report(
            case_dir,
            case_id,
            pcap_path,
            pcap_sha256,
            csv_path,
            csv_hash,
            prediction_path,
            prediction_hash,
            current_case["shap_path"],
            current_case["shap_sha256"],
            total_flows,
            benign_count,
            malicious_count,
            model_name
        )
    )

    current_case[
        "report_path"
    ] = report_path

    current_case[
        "report_sha256"
    ] = report_hash

    # ========================================================
    # COMPLETE
    # ========================================================

    log_fn(
        "",
        None
    )

    log_fn(
        "[+] FORENSIC PIPELINE COMPLETE",
        "success"
    )

    log_fn(
        f"[+] Case ID: {case_id}",
        "info"
    )

    log_fn(
        f"[+] Evidence SHA-256: {pcap_sha256}",
        "info"
    )

    log_fn(
        f"[+] Flow extractor: CICFlowMeter v4",
        "info"
    )

    log_fn(
        f"[+] ML dataset: {model_name}",
        "info"
    )

    log_fn(
        f"[+] Total flows: {total_flows}",
        "info"
    )

    log_fn(
        f"[+] AI threat findings: {malicious_count}",
        "error"
        if malicious_count > 0
        else "success"
    )

    log_fn(
        "[!] AI findings require investigator review.",
        "info"
    )

    return current_case, shap_results


# ============================================================
# HUMAN INVESTIGATOR REVIEW
# ============================================================

def save_investigator_review(
    current_case,
    case_output_dir,
    decision,
    comment
):
    """
    Mutates current_case in place with the review decision,
    writes the review JSON + appends to the case audit log,
    and returns the review file SHA-256.
    """

    case_id = current_case.get(
        "case_id"
    )

    if not case_id:

        raise ValueError(
            "No forensic case is currently loaded."
        )

    current_case[
        "investigator_comment"
    ] = comment

    current_case[
        "investigator_decision"
    ] = decision

    current_case[
        "review_timestamp"
    ] = utc_timestamp()

    case_dir = os.path.join(
        case_output_dir,
        case_id
    )

    review_path = os.path.join(
        case_dir,
        f"{case_id}_investigator_review.json"
    )

    with open(
        review_path,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            current_case,
            f,
            indent=4
        )

    review_hash = calculate_sha256(
        review_path
    )

    audit_path = os.path.join(
        case_dir,
        f"{case_id}_audit.log"
    )

    with open(
        audit_path,
        "a",
        encoding="utf-8"
    ) as f:

        f.write(
            f"{utc_timestamp()} | HUMAN_REVIEW | "
            f"Decision={decision} | "
            f"ReviewSHA256={review_hash}\n"
        )

    return review_hash