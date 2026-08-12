import os
import json
import subprocess
from datetime import datetime

import pandas as pd

from services.utils import calculate_sha256, safe_filename, utc_timestamp
from services.model_service import validate_model_schema
from services.zeek_service import parse_zeek_conn_log, clean_features
from services.shap_service import generate_shap_explanation


# ============================================================
# INTERNAL CSV ARTIFACT
# ============================================================

def save_internal_csv(df, case_dir, case_id):
    csv_path = os.path.join(case_dir, f"{case_id}_zeek_features.csv")
    df.to_csv(csv_path, index=False)
    csv_hash = calculate_sha256(csv_path)
    return csv_path, csv_hash


# ============================================================
# PREDICTION ARTIFACT
# ============================================================

def save_prediction_results(X, predictions, threat_probabilities, case_dir, case_id):
    records = []

    for i, prediction in enumerate(predictions):
        threat_probability = None

        if threat_probabilities is not None:
            threat_probability = float(threat_probabilities[i])

        records.append({
            "flow_index": int(i),
            "ai_prediction": str(prediction),
            "threat_probability": threat_probability
        })

    prediction_path = os.path.join(case_dir, f"{case_id}_predictions.json")

    with open(prediction_path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=4)

    prediction_hash = calculate_sha256(prediction_path)

    return prediction_path, prediction_hash


# ============================================================
# FORENSIC REPORT
# ============================================================

def generate_forensic_report(
    case_dir, case_id, pcap_path, pcap_sha256,
    csv_path, csv_sha256, prediction_path, prediction_sha256,
    shap_path, shap_sha256, total_flows, benign_flows, threat_flows
):
    report = {
        "case_information": {
            "case_id": case_id,
            "analysis_timestamp_utc": utc_timestamp(),
            "pcap_filename": safe_filename(pcap_path),
            "pcap_path": pcap_path,
            "pcap_sha256": pcap_sha256
        },
        "analysis_pipeline": [
            "PCAP / PCAPNG",
            "SHA-256 Integrity Check",
            "Zeek Feature Extraction",
            "Internal CSV / DataFrame Generation",
            "Schema Validation",
            "Data Cleaning",
            "Required Feature Selection",
            "Random Forest Prediction",
            "SHAP Explanation",
            "Human Investigator Review",
            "Forensic Report and Audit Log"
        ],
        "artifacts": {
            "generated_csv": {"path": csv_path, "sha256": csv_sha256},
            "predictions": {"path": prediction_path, "sha256": prediction_sha256},
            "shap_explanation": {"path": shap_path, "sha256": shap_sha256}
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

    report_path = os.path.join(case_dir, f"{case_id}_forensic_report.json")

    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    report_hash = calculate_sha256(report_path)

    return report_path, report_hash


# ============================================================
# MAIN FORENSIC PIPELINE
# ============================================================

def run_forensic_pipeline(
    pcap_path, model, case_output_dir, log_fn,
    on_metrics_ready=None
):
    """
    Runs the full pcap -> csv -> prediction -> SHAP -> report pipeline.

    log_fn(message, tag=None) is called for every progress line
    (the view layer wires this to its own log console).

    on_metrics_ready(total, benign, threat), if given, fires as soon as
    predictions are available -- before SHAP -- so the UI can update the
    dashboard cards without waiting on the (slower) SHAP stage.

    Returns (current_case, shap_results) on success.
    Raises on any failure -- the caller (view layer) is responsible for
    catching it and showing an error dialog.
    """

    case_id = datetime.now().strftime("CASE_%Y%m%d_%H%M%S_%f")
    case_dir = os.path.join(case_output_dir, case_id)
    os.makedirs(case_dir, exist_ok=True)

    current_case = {
        "case_id": case_id,
        "pcap_path": pcap_path,
        "pcap_sha256": None,
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

    # ====================================================
    # STAGE 1 — INTEGRITY CHECK
    # ====================================================

    log_fn("[Stage 1/9] Calculating SHA-256 evidence hash...", "info")

    pcap_sha256 = calculate_sha256(pcap_path)
    current_case["pcap_sha256"] = pcap_sha256

    log_fn(f"[+] PCAP SHA-256: {pcap_sha256}", "success")

    # Reject empty pcap before wasting time on extraction
    if os.path.getsize(pcap_path) == 0:
        raise ValueError("The uploaded PCAP file is empty (0 bytes).")

    # ====================================================
    # STAGE 2 — ZEEK EXTRACTION
    # ====================================================

    log_fn("[Stage 2/9] Running Zeek feature extraction...", "info")

    zeek_dir = os.path.join(case_dir, "zeek")
    os.makedirs(zeek_dir, exist_ok=True)

    result = subprocess.run(
        ["zeek", "-r", pcap_path],
        cwd=zeek_dir,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise RuntimeError("Zeek execution failed:\n" + result.stderr)

    conn_log_path = os.path.join(zeek_dir, "conn.log")

    if not os.path.exists(conn_log_path):
        raise FileNotFoundError("Zeek did not generate conn.log.")

    # ====================================================
    # STAGE 3 — INTERNAL CSV / DATAFRAME
    # ====================================================

    log_fn(
        "[Stage 3/9] Converting Zeek telemetry to internal DataFrame/CSV...",
        "info"
    )

    extracted_df = parse_zeek_conn_log(conn_log_path)

    if extracted_df.empty:
        raise ValueError("No network flows were extracted from PCAP.")

    csv_path, csv_hash = save_internal_csv(extracted_df, case_dir, case_id)
    current_case["generated_csv_path"] = csv_path
    current_case["generated_csv_sha256"] = csv_hash

    log_fn(f"[+] Internal CSV generated: {csv_path}", "success")
    log_fn(f"[+] Internal CSV SHA-256: {csv_hash}", "info")

    # ====================================================
    # STAGE 4 — SCHEMA VALIDATION
    # ====================================================

    log_fn("[Stage 4/9] Validating model feature schema...", "info")

    expected_features, missing_features = validate_model_schema(model, extracted_df)

    if missing_features:
        raise ValueError(
            "Required model features are missing from Zeek-derived data:\n\n"
            + "\n".join(missing_features)
            + "\n\nThe model will NOT be executed because "
              "the feature schema cannot be safely satisfied."
        )

    log_fn("[+] Model schema validated successfully.", "success")

    # ====================================================
    # STAGE 5 — DATA CLEANING
    # ====================================================

    log_fn("[Stage 5/9] Cleaning extracted data...", "info")

    cleaned_df = clean_features(extracted_df)

    # ====================================================
    # STAGE 6 — REQUIRED FEATURE SELECTION
    # ====================================================

    log_fn("[Stage 6/9] Selecting required model features...", "info")

    X = cleaned_df[expected_features].copy()

    non_numeric_columns = [
        col for col in X.columns
        if not pd.api.types.is_numeric_dtype(X[col])
    ]

    if non_numeric_columns:
        raise ValueError(
            "Non-numeric features remain after data cleaning:\n"
            + "\n".join(non_numeric_columns)
        )

    log_fn(f"[+] Selected {len(X.columns)} model features.", "success")

    # ====================================================
    # STAGE 7 — RANDOM FOREST PREDICTION
    # ====================================================

    log_fn("[Stage 7/9] Running Random Forest inference...", "info")

    predictions = model.predict(X)

    threat_probabilities = None

    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(X)
        classes = list(model.classes_)

        if 1 in classes:
            threat_class_index = classes.index(1)
            threat_probabilities = probabilities[:, threat_class_index]

    total_flows = len(predictions)

    malicious_count = sum(
        1 for p in predictions if p in [1, True, "Attack", "attack"]
    )

    benign_count = total_flows - malicious_count

    current_case["total_flows"] = total_flows
    current_case["benign_flows"] = benign_count
    current_case["threat_flows"] = malicious_count

    prediction_path, prediction_hash = save_prediction_results(
        X, predictions, threat_probabilities, case_dir, case_id
    )
    current_case["prediction_path"] = prediction_path
    current_case["prediction_sha256"] = prediction_hash

    if on_metrics_ready:
        on_metrics_ready(total_flows, benign_count, malicious_count)

    # ====================================================
    # STAGE 8 — SHAP
    # ====================================================

    log_fn("[Stage 8/9] Generating explainable AI output...", "info")

    shap_results, shap_metadata = generate_shap_explanation(
        model, X, predictions, case_id, case_dir, log_fn
    )

    if shap_metadata:
        current_case["shap_path"] = shap_metadata["shap_path"]
        current_case["shap_sha256"] = shap_metadata["shap_sha256"]

    # ====================================================
    # STAGE 9 — INITIAL FORENSIC REPORT
    # ====================================================

    log_fn("[Stage 9/9] Generating forensic case report...", "info")

    report_path, report_hash = generate_forensic_report(
        case_dir, case_id, pcap_path, pcap_sha256,
        csv_path, csv_hash, prediction_path, prediction_hash,
        current_case["shap_path"], current_case["shap_sha256"],
        total_flows, benign_count, malicious_count
    )

    current_case["report_path"] = report_path
    current_case["report_sha256"] = report_hash

    # ====================================================
    # COMPLETE
    # ====================================================

    log_fn("", None)
    log_fn("[+] FORENSIC PIPELINE COMPLETE", "success")
    log_fn(f"[+] Case ID: {case_id}", "info")
    log_fn(f"[+] Evidence SHA-256: {pcap_sha256}", "info")
    log_fn(f"[+] Total flows: {total_flows}", "info")
    log_fn(
        f"[+] AI threat findings: {malicious_count}",
        "error" if malicious_count > 0 else "success"
    )
    log_fn("[!] AI findings require investigator review.", "info")

    return current_case, shap_results


# ============================================================
# HUMAN INVESTIGATOR REVIEW
# ============================================================

def save_investigator_review(current_case, case_output_dir, decision, comment):
    """
    Mutates current_case in place with the review decision, writes the
    review JSON + appends to the case's audit log, and returns the
    review file's SHA-256 (for display back to the investigator).
    """

    case_id = current_case.get("case_id")

    if not case_id:
        raise ValueError("No forensic case is currently loaded.")

    current_case["investigator_comment"] = comment
    current_case["investigator_decision"] = decision
    current_case["review_timestamp"] = utc_timestamp()

    case_dir = os.path.join(case_output_dir, case_id)

    review_path = os.path.join(case_dir, f"{case_id}_investigator_review.json")

    with open(review_path, "w", encoding="utf-8") as f:
        json.dump(current_case, f, indent=4)

    review_hash = calculate_sha256(review_path)

    audit_path = os.path.join(case_dir, f"{case_id}_audit.log")

    with open(audit_path, "a", encoding="utf-8") as f:
        f.write(
            f"{utc_timestamp()} | HUMAN_REVIEW | "
            f"Decision={decision} | ReviewSHA256={review_hash}\n"
        )

    return review_hash
