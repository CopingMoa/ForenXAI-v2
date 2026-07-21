import os
import sys
import json
import hashlib
import subprocess
import threading
import shutil
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd

import tkinter as tk
from tkinter import ttk, messagebox
from tkinterdnd2 import DND_FILES, TkinterDnD

# ============================================================
# MACHINE LEARNING
# ============================================================

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

# ============================================================
# VISUALIZATION
# ============================================================

import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# ============================================================
# XAI
# ============================================================

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False


# ============================================================
# CONFIGURATION
# ============================================================

MODEL_PATH = (
    r"C:\Users\HOME PC\Downloads"
    r"\Processed-Copy\stage5_output\rf.pkl"
)

CASE_OUTPUT_DIR = (
    r"C:\Users\HOME PC\Downloads"
    r"ForenXAI_Cases"
)

os.makedirs(
    CASE_OUTPUT_DIR,
    exist_ok=True
)


# ============================================================
# GLOBAL STATE
# ============================================================

selected_pcap = None
model = None

current_case = {
    "case_id": None,
    "pcap_path": None,
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


# ============================================================
# MODEL LOADING
# ============================================================

try:

    if os.path.exists(MODEL_PATH):

        model = joblib.load(
            MODEL_PATH
        )

        print(
            "[+] Random Forest model loaded successfully."
        )

    else:

        print(
            "[!] Model file not found:"
        )

        print(
            MODEL_PATH
        )

except Exception as e:

    print(
        f"[!] Error loading model: {e}"
    )


# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def utc_timestamp():

    return datetime.now(
        timezone.utc
    ).isoformat()


def calculate_sha256(
    file_path
):

    sha256 = hashlib.sha256()

    with open(
        file_path,
        "rb"
    ) as f:

        for chunk in iter(
            lambda: f.read(1024 * 1024),
            b""
        ):

            sha256.update(
                chunk
            )

    return sha256.hexdigest()


def safe_filename(
    path
):

    return os.path.basename(
        path
    )


# ============================================================
# LOGGING
# ============================================================

def write_log(
    message,
    tag=None
):

    def append():

        log_console.config(
            state=tk.NORMAL
        )

        if tag:

            log_console.insert(
                tk.END,
                message + "\n",
                tag
            )

        else:

            log_console.insert(
                tk.END,
                message + "\n"
            )

        log_console.see(
            tk.END
        )

        log_console.config(
            state=tk.DISABLED
        )

    root.after(
        0,
        append
    )


# ============================================================
# DASHBOARD
# ============================================================

def update_dashboard_metrics(
    total,
    benign,
    threat
):

    def update():

        lbl_val_total.config(
            text=f"{total:,}"
        )

        lbl_val_benign.config(
            text=f"{benign:,}"
        )

        lbl_val_threat.config(
            text=f"{threat:,}"
        )

        if threat > 0:

            card_threat.config(
                bg="#3F1D24",
                highlightbackground="#EF4444"
            )

            lbl_val_threat.config(
                bg="#3F1D24",
                fg="#EF4444"
            )

        else:

            card_threat.config(
                bg="#27293D",
                highlightbackground="#374151"
            )

            lbl_val_threat.config(
                bg="#27293D",
                fg="#9CA3AF"
            )

    root.after(
        0,
        update
    )


# ============================================================
# ZEEK FEATURE EXTRACTION
# ============================================================

def parse_zeek_conn_log(
    log_path
):

    with open(
        log_path,
        "r",
        errors="replace"
    ) as f:

        lines = f.readlines()

    fields_line = next(
        (
            line
            for line in lines
            if line.startswith(
                "#fields"
            )
        ),
        None
    )

    if fields_line is None:

        raise ValueError(
            "Zeek conn.log does not contain a #fields definition."
        )

    columns = (
        fields_line
        .strip()
        .split("\t")[1:]
    )

    data_rows = [
        line.strip().split("\t")
        for line in lines
        if not line.startswith("#")
        and line.strip()
    ]

    if not data_rows:

        return pd.DataFrame(
            columns=columns
        )

    df = pd.DataFrame(
        data_rows,
        columns=columns
    )

    # Rename Zeek fields
    df.rename(
        columns={
            "id.orig_h": "src_ip_zeek",
            "id.orig_p": "src_port_zeek",
            "id.resp_h": "dest_ip_zeek",
            "id.resp_p": "dest_port_zeek"
        },
        inplace=True
    )

    # Zeek missing values
    df.replace(
        "-",
        np.nan,
        inplace=True
    )

    numeric_cols = [

        "duration",

        "orig_bytes",

        "resp_bytes",

        "orig_pkts",

        "resp_pkts",

        "orig_ip_bytes",

        "resp_ip_bytes",

        "src_port_zeek",

        "dest_port_zeek",

        "missed_bytes"

    ]

    for col in numeric_cols:

        if col in df.columns:

            df[col] = pd.to_numeric(
                df[col],
                errors="coerce"
            )

    return df


# ============================================================
# DATA CLEANING
# ============================================================

def clean_features(
    df
):

    df = df.copy()

    # Replace infinite values
    df.replace(
        [
            np.inf,
            -np.inf
        ],
        np.nan,
        inplace=True
    )

    # Convert object columns where possible
    for col in df.columns:

        if df[col].dtype == "object":

            converted = pd.to_numeric(
                df[col],
                errors="coerce"
            )

            # Only replace if meaningful numeric conversion exists
            if converted.notna().sum() > 0:

                df[col] = converted

    # Fill numerical missing values
    numeric_cols = df.select_dtypes(
        include=[np.number]
    ).columns

    for col in numeric_cols:

        df[col] = df[col].fillna(
            0
        )

    return df


# ============================================================
# MODEL SCHEMA VALIDATION
# ============================================================

def get_expected_features():

    if model is None:

        raise RuntimeError(
            "Machine learning model is not loaded."
        )

    if not hasattr(
        model,
        "feature_names_in_"
    ):

        raise RuntimeError(
            "The trained model does not contain "
            "feature_names_in_. "
            "The inference schema cannot be safely verified."
        )

    return list(
        model.feature_names_in_
    )


def validate_model_schema(
    df
):

    expected_features = get_expected_features()

    missing_features = [

        feature

        for feature in expected_features

        if feature not in df.columns

    ]

    return (
        expected_features,
        missing_features
    )


# ============================================================
# INTERNAL CSV ARTIFACT
# ============================================================

def save_internal_csv(
    df,
    case_dir,
    case_id
):

    csv_path = os.path.join(
        case_dir,
        f"{case_id}_zeek_features.csv"
    )

    df.to_csv(
        csv_path,
        index=False
    )

    csv_hash = calculate_sha256(
        csv_path
    )

    return (
        csv_path,
        csv_hash
    )


# ============================================================
# SHAP EXPLANATION
# ============================================================

def normalize_shap_values(
    shap_values,
    X
):

    """
    Normalize SHAP output into:

        shape = (n_samples, n_features)

    Supports common SHAP TreeExplainer formats.
    """

    if isinstance(
        shap_values,
        list
    ):

        # Binary classification:
        # index 1 normally represents threat class
        if len(shap_values) > 1:

            values = shap_values[1]

        else:

            values = shap_values[0]

    else:

        values = shap_values

    values = np.asarray(
        values
    )

    # New SHAP versions may return:
    # samples x features x classes
    if values.ndim == 3:

        if values.shape[2] > 1:

            values = values[:, :, 1]

        else:

            values = values[:, :, 0]

    return values


def generate_shap_explanation(
    X,
    predictions,
    case_id,
    case_dir
):

    if not SHAP_AVAILABLE:

        write_log(
            "[!] SHAP is not installed. "
            "Explanation stage skipped.",
            "error"
        )

        return None, None

    try:

        write_log(
            "[*] Generating SHAP explanations...",
            "info"
        )

        explainer = shap.TreeExplainer(
            model
        )

        raw_shap_values = explainer.shap_values(
            X
        )

        shap_values = normalize_shap_values(
            raw_shap_values,
            X
        )

        if shap_values.shape[1] != len(
            X.columns
        ):

            raise ValueError(
                "SHAP output feature count does not "
                "match model input feature count."
            )

        explanation_records = []

        for i in range(
            len(X)
        ):

            feature_values = X.iloc[i]

            shap_row = shap_values[i]

            ranked_features = sorted(

                zip(
                    X.columns,
                    shap_row
                ),

                key=lambda x: abs(
                    float(x[1])
                ),

                reverse=True
            )

            top_features = []

            for feature, value in ranked_features[:10]:

                top_features.append(
                    {
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
                    }
                )

            explanation_records.append(
                {
                    "flow_index": int(
                        i
                    ),

                    "prediction": str(
                        predictions[i]
                    ),

                    "top_features": top_features
                }
            )

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

        # Create global SHAP importance chart
        mean_importance = np.mean(
            np.abs(
                shap_values
            ),
            axis=0
        )

        importance_df = pd.DataFrame(
            {
                "feature": X.columns,
                "importance": mean_importance
            }
        )

        importance_df.sort_values(
            "importance",
            ascending=True,
            inplace=True
        )

        top_global = importance_df.tail(
            15
        )

        fig, ax = plt.subplots(
            figsize=(
                8,
                5
            )
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

        write_log(
            "[+] SHAP explanations generated.",
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

    except Exception as e:

        write_log(
            f"[!] SHAP explanation failed: {e}",
            "error"
        )

        return (
            None,
            None
        )


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

    for i, prediction in enumerate(
        predictions
    ):

        threat_probability = None

        if threat_probabilities is not None:

            threat_probability = float(
                threat_probabilities[i]
            )

        records.append(
            {
                "flow_index": int(
                    i
                ),

                "ai_prediction": str(
                    prediction
                ),

                "threat_probability": (
                    threat_probability
                )
            }
        )

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

    return (
        prediction_path,
        prediction_hash
    )


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
    threat_flows
):

    report = {

        "case_information": {

            "case_id": case_id,

            "analysis_timestamp_utc":
                utc_timestamp(),

            "pcap_filename":
                safe_filename(
                    pcap_path
                ),

            "pcap_path":
                pcap_path,

            "pcap_sha256":
                pcap_sha256

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

            "total_flows":
                total_flows,

            "benign_flows":
                benign_flows,

            "threat_flows":
                threat_flows,

            "note":
                "AI predictions are analytical findings "
                "and do not constitute confirmed ground truth."

        },

        "human_review": {

            "decision":
                "Pending",

            "comment":
                "",

            "review_timestamp":
                None

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

    return (
        report_path,
        report_hash
    )


# ============================================================
# MAIN FORENSIC PIPELINE
# ============================================================

def pipeline_worker(
    pcap_path
):

    global current_case

    try:

        # ====================================================
        # CASE INITIALIZATION
        # ====================================================

        case_id = datetime.now().strftime(
            "CASE_%Y%m%d_%H%M%S_%f"
        )

        case_dir = os.path.join(
            CASE_OUTPUT_DIR,
            case_id
        )

        os.makedirs(
            case_dir,
            exist_ok=True
        )

        current_case = {

            "case_id":
                case_id,

            "pcap_path":
                pcap_path,

            "pcap_sha256":
                None,

            "generated_csv_path":
                None,

            "generated_csv_sha256":
                None,

            "prediction_path":
                None,

            "prediction_sha256":
                None,

            "shap_path":
                None,

            "shap_sha256":
                None,

            "report_path":
                None,

            "report_sha256":
                None,

            "total_flows":
                0,

            "benign_flows":
                0,

            "threat_flows":
                0,

            "investigator_decision":
                "Pending",

            "investigator_comment":
                "",

            "review_timestamp":
                None

        }

        # ====================================================
        # STAGE 1 — INTEGRITY CHECK
        # ====================================================

        write_log(
            "[Stage 1/9] Calculating SHA-256 evidence hash...",
            "info"
        )

        pcap_sha256 = calculate_sha256(
            pcap_path
        )

        current_case[
            "pcap_sha256"
        ] = pcap_sha256

        write_log(
            f"[+] PCAP SHA-256: {pcap_sha256}",
            "success"
        )

        # ====================================================
        # STAGE 2 — ZEEK EXTRACTION
        # ====================================================

        write_log(
            "[Stage 2/9] Running Zeek feature extraction...",
            "info"
        )

        work_dir = os.path.dirname(
            pcap_path
        ) or "."

        # Use case-specific temporary extraction directory
        zeek_dir = os.path.join(
            case_dir,
            "zeek"
        )

        os.makedirs(
            zeek_dir,
            exist_ok=True
        )

        result = subprocess.run(

            [
                "zeek",
                "-r",
                pcap_path
            ],

            cwd=zeek_dir,

            capture_output=True,

            text=True

        )

        if result.returncode != 0:

            raise RuntimeError(
                "Zeek execution failed:\n"
                + result.stderr
            )

        conn_log_path = os.path.join(
            zeek_dir,
            "conn.log"
        )

        if not os.path.exists(
            conn_log_path
        ):

            raise FileNotFoundError(
                "Zeek did not generate conn.log."
            )

        # ====================================================
        # STAGE 3 — INTERNAL CSV / DATAFRAME
        # ====================================================

        write_log(
            "[Stage 3/9] Converting Zeek telemetry "
            "to internal DataFrame/CSV...",
            "info"
        )

        extracted_df = parse_zeek_conn_log(
            conn_log_path
        )

        if extracted_df.empty:

            raise ValueError(
                "No network flows were extracted from PCAP."
            )

        csv_path, csv_hash = save_internal_csv(
            extracted_df,
            case_dir,
            case_id
        )

        current_case[
            "generated_csv_path"
        ] = csv_path

        current_case[
            "generated_csv_sha256"
        ] = csv_hash

        write_log(
            f"[+] Internal CSV generated: {csv_path}",
            "success"
        )

        write_log(
            f"[+] Internal CSV SHA-256: {csv_hash}",
            "info"
        )

        # ====================================================
        # STAGE 4 — SCHEMA VALIDATION
        # ====================================================

        write_log(
            "[Stage 4/9] Validating model feature schema...",
            "info"
        )

        expected_features, missing_features = \
            validate_model_schema(
                extracted_df
            )

        if missing_features:

            raise ValueError(

                "Required model features are missing "
                "from Zeek-derived data:\n\n"

                + "\n".join(
                    missing_features
                )

                + "\n\n"
                "The model will NOT be executed because "
                "the feature schema cannot be safely satisfied."

            )

        write_log(
            "[+] Model schema validated successfully.",
            "success"
        )

        # ====================================================
        # STAGE 5 — DATA CLEANING
        # ====================================================

        write_log(
            "[Stage 5/9] Cleaning extracted data...",
            "info"
        )

        cleaned_df = clean_features(
            extracted_df
        )

        # ====================================================
        # STAGE 6 — REQUIRED FEATURE SELECTION
        # ====================================================

        write_log(
            "[Stage 6/9] Selecting required model features...",
            "info"
        )

        X = cleaned_df[
            expected_features
        ].copy()

        # Final numeric validation
        non_numeric_columns = [

            col

            for col in X.columns

            if not pd.api.types.is_numeric_dtype(
                X[col]
            )

        ]

        if non_numeric_columns:

            raise ValueError(

                "Non-numeric features remain after "
                "data cleaning:\n"

                + "\n".join(
                    non_numeric_columns
                )

            )

        write_log(
            f"[+] Selected {len(X.columns)} model features.",
            "success"
        )

        # ====================================================
        # STAGE 7 — RANDOM FOREST PREDICTION
        # ====================================================

        write_log(
            "[Stage 7/9] Running Random Forest inference...",
            "info"
        )

        predictions = model.predict(
            X
        )

        # ====================================================
        # THREAT PROBABILITY
        # ====================================================

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

                threat_class_index = classes.index(
                    1
                )

                threat_probabilities = \
                    probabilities[
                        :,
                        threat_class_index
                    ]

        total_flows = len(
            predictions
        )

        malicious_count = sum(

            1

            for p in predictions

            if p in [
                1,
                True,
                "Attack",
                "attack"
            ]

        )

        benign_count = (
            total_flows
            -
            malicious_count
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

        # Save predictions
        prediction_path, prediction_hash = \
            save_prediction_results(

                X,

                predictions,

                threat_probabilities,

                case_dir,

                case_id

            )

        current_case[
            "prediction_path"
        ] = prediction_path

        current_case[
            "prediction_sha256"
        ] = prediction_hash

        update_dashboard_metrics(

            total_flows,

            benign_count,

            malicious_count

        )

        # ====================================================
        # STAGE 8 — SHAP
        # ====================================================

        write_log(
            "[Stage 8/9] Generating explainable AI output...",
            "info"
        )

        shap_results, shap_metadata = \
            generate_shap_explanation(

                X,

                predictions,

                case_id,

                case_dir

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

        # ====================================================
        # STAGE 9 — INITIAL FORENSIC REPORT
        # ====================================================

        write_log(
            "[Stage 9/9] Generating forensic case report...",
            "info"
        )

        report_path, report_hash = \
            generate_forensic_report(

                case_dir,

                case_id,

                pcap_path,

                pcap_sha256,

                csv_path,

                csv_hash,

                prediction_path,

                prediction_hash,

                current_case[
                    "shap_path"
                ],

                current_case[
                    "shap_sha256"
                ],

                total_flows,

                benign_count,

                malicious_count

            )

        current_case[
            "report_path"
        ] = report_path

        current_case[
            "report_sha256"
        ] = report_hash

        # ====================================================
        # UPDATE XAI TAB
        # ====================================================

        update_xai_results(

            case_id,

            pcap_sha256,

            total_flows,

            benign_count,

            malicious_count,

            shap_results

        )

        # ====================================================
        # COMPLETE
        # ====================================================

        write_log(
            "",
            None
        )

        write_log(
            "[+] FORENSIC PIPELINE COMPLETE",
            "success"
        )

        write_log(
            f"[+] Case ID: {case_id}",
            "info"
        )

        write_log(
            f"[+] Evidence SHA-256: {pcap_sha256}",
            "info"
        )

        write_log(
            f"[+] Total flows: {total_flows}",
            "info"
        )

        write_log(
            f"[+] AI threat findings: {malicious_count}",
            "error"
            if malicious_count > 0
            else "success"
        )

        write_log(
            "[!] AI findings require investigator review.",
            "info"
        )

    except Exception as err:

        write_log(
            f"\n[!] FORENSIC PIPELINE FAILED: {str(err)}",
            "error"
        )

        root.after(

            0,

            lambda: messagebox.showerror(

                "Forensic Pipeline Error",

                str(err)

            )

        )

    finally:

        root.after(

            0,

            lambda: btn_analyze.config(

                state=tk.NORMAL,

                text="Analyze PCAP",

                bg="#3B82F6"

            )

        )


# ============================================================
# ANALYSIS TRIGGER
# ============================================================

def analyze_trigger():

    if not selected_pcap:

        messagebox.showwarning(

            "Warning",

            "Please upload a PCAP or PCAPNG file first."

        )

        return

    if model is None:

        messagebox.showerror(

            "Error",

            "Random Forest model is not loaded."

        )

        return

    btn_analyze.config(

        state=tk.DISABLED,

        text="Analyzing Evidence...",

        bg="#4B5563"

    )

    threading.Thread(

        target=pipeline_worker,

        args=(selected_pcap,),

        daemon=True

    ).start()


# ============================================================
# XAI RESULTS
# ============================================================

def update_xai_results(

    case_id,

    sha256,

    total,

    benign,

    threats,

    shap_results

):

    def update():

        lbl_case_id.config(

            text=f"Case ID: {case_id}"

        )

        lbl_hash.config(

            text=f"Evidence SHA-256: {sha256}"

        )

        lbl_xai_summary.config(

            text=(

                f"Flows: {total} | "

                f"Benign AI Findings: {benign} | "

                f"Threat AI Findings: {threats}"

            )

        )

        txt_xai.config(

            state=tk.NORMAL

        )

        txt_xai.delete(

            "1.0",

            tk.END

        )

        if shap_results:

            for result in shap_results[:20]:

                txt_xai.insert(

                    tk.END,

                    f"\nFlow {result['flow_index']}"

                    f" → AI Prediction: "

                    f"{result['prediction']}\n"

                )

                txt_xai.insert(

                    tk.END,

                    "Top Contributing Features:\n"

                )

                for feature in result[
                    "top_features"
                ]:

                    direction = (

                        "supports"

                        if feature[
                            "shap_value"
                        ] > 0

                        else "opposes"

                    )

                    txt_xai.insert(

                        tk.END,

                        f"  • "

                        f"{feature['feature']} = "

                        f"{feature['feature_value']} "

                        f"| SHAP = "

                        f"{feature['shap_value']:.5f} "

                        f"| {direction} threat prediction\n"

                    )

                txt_xai.insert(

                    tk.END,

                    "\n"

                )

        else:

            txt_xai.insert(

                tk.END,

                "No SHAP explanation available."

            )

        txt_xai.config(

            state=tk.DISABLED

        )

    root.after(

        0,

        update

    )


# ============================================================
# HUMAN INVESTIGATOR REVIEW
# ============================================================

def save_investigator_review():

    global current_case

    case_id = current_case.get(
        "case_id"
    )

    if not case_id:

        messagebox.showwarning(

            "Review",

            "No forensic case is currently loaded."

        )

        return

    comment = txt_investigator_comment.get(

        "1.0",

        tk.END

    ).strip()

    decision = investigator_decision.get()

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

        CASE_OUTPUT_DIR,

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

    # Audit log
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

            f"{utc_timestamp()} | "

            f"HUMAN_REVIEW | "

            f"Decision={decision} | "

            f"ReviewSHA256={review_hash}\n"

        )

    messagebox.showinfo(

        "Review Saved",

        "Investigator review saved successfully.\n\n"

        f"Decision: {decision}\n\n"

        f"Review SHA-256:\n{review_hash}"

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
# matrix cannot be legitimately calculated from that case.
#
# This tab is ONLY for a labeled research/test dataset.
# ============================================================

def run_evaluation(
    csv_path
):

    try:

        if model is None:

            raise RuntimeError(
                "Random Forest model is not loaded."
            )

        df = pd.read_csv(

            csv_path

        )

        if "label_binary" not in df.columns:

            raise ValueError(

                "The evaluation dataset must contain "
                "'label_binary' as ground truth."

            )

        y_true = df[
            "label_binary"
        ].astype(
            int
        ).values

        expected_features = get_expected_features()

        missing_features = [

            c

            for c in expected_features

            if c not in df.columns

        ]

        if missing_features:

            raise ValueError(

                "Evaluation dataset is missing required features:\n"

                + "\n".join(

                    missing_features

                )

            )

        X = df[
            expected_features
        ].copy()

        X = clean_features(

            X

        )

        y_pred = model.predict(

            X

        ).astype(

            int

        )

        y_probs = None

        if hasattr(

            model,

            "predict_proba"

        ):

            classes = list(

                model.classes_

            )

            if 1 in classes:

                class_index = classes.index(

                    1

                )

                y_probs = model.predict_proba(

                    X

                )[:, class_index]

        cm = confusion_matrix(

            y_true,

            y_pred,

            labels=[

                0,

                1

            ]

        )

        tn, fp, fn, tp = cm.ravel()

        acc = accuracy_score(

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

        specificity = (

            tn / (tn + fp)

            if (tn + fp) > 0

            else 0

        )

        fpr = (

            fp / (fp + tn)

            if (fp + tn) > 0

            else 0

        )

        fnr = (

            fn / (fn + tp)

            if (fn + tp) > 0

            else 0

        )

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

        roc_auc = 0.0

        pr_auc = 0.0

        if y_probs is not None:

            if len(
                np.unique(
                    y_true
                )
            ) == 2:

                roc_auc = roc_auc_score(

                    y_true,

                    y_probs

                )

                p, r, _ = precision_recall_curve(

                    y_true,

                    y_probs

                )

                pr_auc = auc(

                    r,

                    p

                )

        report = classification_report(

            y_true,

            y_pred,

            output_dict=True,

            zero_division=0

        )

        def update_ui():

            lbl_acc.config(

                text=f"{acc:.4f}"

            )

            lbl_prec.config(

                text=f"{precision:.4f}"

            )

            lbl_rec.config(

                text=f"{recall:.4f}"

            )

            lbl_spec.config(

                text=f"{specificity:.4f}"

            )

            lbl_f1.config(

                text=f"{f1:.4f}"

            )

            lbl_fpr.config(

                text=f"{fpr:.4f}"

            )

            lbl_fnr.config(

                text=f"{fnr:.4f}"

            )

            lbl_roc.config(

                text=f"{roc_auc:.4f}"

            )

            lbl_pr.config(

                text=f"{pr_auc:.4f}"

            )

            lbl_macro.config(

                text=f"{macro_f1:.4f}"

            )

            lbl_weight.config(

                text=f"{weighted_f1:.4f}"

            )

            report_str = ""

            if "0" in report:

                report_str += (

                    "Class 0 (Benign)\n"

                    f"Precision: "

                    f"{report['0']['precision']:.4f}\n"

                    f"Recall: "

                    f"{report['0']['recall']:.4f}\n"

                    f"F1: "

                    f"{report['0']['f1-score']:.4f}\n"

                    f"Support: "

                    f"{report['0']['support']}\n\n"

                )

            if "1" in report:

                report_str += (

                    "Class 1 (Threat)\n"

                    f"Precision: "

                    f"{report['1']['precision']:.4f}\n"

                    f"Recall: "

                    f"{report['1']['recall']:.4f}\n"

                    f"F1: "

                    f"{report['1']['f1-score']:.4f}\n"

                    f"Support: "

                    f"{report['1']['support']}\n"

                )

            txt_report.config(

                state=tk.NORMAL

            )

            txt_report.delete(

                "1.0",

                tk.END

            )

            txt_report.insert(

                tk.END,

                report_str

            )

            txt_report.config(

                state=tk.DISABLED

            )

            # Clear old matrix
            for widget in cm_frame.winfo_children():

                widget.destroy()

            fig, ax = plt.subplots(

                figsize=(4.5, 3.5)

            )

            sns.heatmap(

                cm,

                annot=True,

                fmt="d",

                cmap="Blues",

                cbar=False,

                xticklabels=[

                    "Benign (0)",

                    "Threat (1)"

                ],

                yticklabels=[

                    "Benign (0)",

                    "Threat (1)"

                ],

                ax=ax

            )

            ax.set_xlabel(

                "Predicted Label"

            )

            ax.set_ylabel(

                "True Label"

            )

            ax.set_title(

                "Confusion Matrix"

            )

            fig.tight_layout()

            canvas = FigureCanvasTkAgg(

                fig,

                master=cm_frame

            )

            canvas.draw()

            canvas.get_tk_widget().pack(

                fill=tk.BOTH,

                expand=True

            )

            plt.close(

                fig

            )

        root.after(

            0,

            update_ui

        )

    except Exception as err:

        root.after(

            0,

            lambda: messagebox.showerror(

                "Evaluation Error",

                str(err)

            )

        )


def eval_drop_file(

    event

):

    raw_path = event.data.strip(

        "{}"

    ).strip(

        '"'

    )

    if raw_path.lower().endswith(

        ".csv"

    ):

        lbl_eval_file.config(

            text=(

                f"Evaluation dataset: "

                f"{os.path.basename(raw_path)}"

            ),

            fg="#10B981"

        )

        threading.Thread(

            target=run_evaluation,

            args=(raw_path,),

            daemon=True

        ).start()

    else:

        lbl_eval_file.config(

            text=(

                "Invalid file. "

                "Drop a labeled evaluation CSV."

            ),

            fg="#EF4444"

        )


# ============================================================
# PCAP DROP
# ============================================================

def pcap_drop_file(

    event

):

    global selected_pcap

    raw_path = event.data.strip(

        "{}"

    ).strip(

        '"'

    )

    if raw_path.lower().endswith(

        (

            ".pcap",

            ".pcapng"

        )

    ):

        selected_pcap = raw_path

        lbl_pcap_file.config(

            text=(

                f"📁 "

                f"{os.path.basename(selected_pcap)}"

            ),

            fg="#10B981"

        )

        write_log(

            f"[+] Evidence selected: "

            f"{os.path.basename(selected_pcap)}",

            "success"

        )

    else:

        selected_pcap = None

        lbl_pcap_file.config(

            text=(

                "Invalid evidence. "

                "Drop a .pcap or .pcapng file."

            ),

            fg="#EF4444"

        )


# ============================================================
# GUI INITIALIZATION
# ============================================================

root = TkinterDnD.Tk()

root.title(

    "ForenXAI"

)

root.geometry(

    "1150x780"

)

root.configure(

    bg="#1E1E2E"

)

root.resizable(

    False,

    False

)


# ============================================================
# STYLE
# ============================================================

style = ttk.Style()

style.theme_use(

    "default"

)

style.configure(

    "TNotebook",

    background="#1E1E2E",

    borderwidth=0

)

style.configure(

    "TNotebook.Tab",

    background="#27293D",

    foreground="white",

    font=(

        "Segoe UI",

        10,

        "bold"

    ),

    padding=[

        15,

        5

    ]

)

style.map(

    "TNotebook.Tab",

    background=[

        (

            "selected",

            "#3B82F6"

        )

    ]

)


# ============================================================
# NOTEBOOK
# ============================================================

notebook = ttk.Notebook(

    root

)

notebook.pack(

    fill="both",

    expand=True,

    padx=15,

    pady=15

)


# ============================================================
# TAB 1 — FORENSIC ANALYSIS
# ============================================================

tab_live = tk.Frame(

    notebook,

    bg="#1E1E2E"

)

notebook.add(

    tab_live,

    text="PCAP Forensic Analysis"

)

top_frame = tk.Frame(

    tab_live,

    bg="#1E1E2E"

)

top_frame.pack(

    fill="x",

    pady=10

)

input_frame = tk.Frame(

    top_frame,

    bg="#27293D",

    highlightbackground="#374151",

    highlightthickness=1

)

input_frame.pack(

    side=tk.LEFT,

    fill="both",

    expand=True,

    padx=(0, 10)

)

tk.Label(

    input_frame,

    text="ForenXAI Forensic Engine",

    font=(

        "Segoe UI",

        16,

        "bold"

    ),

    bg="#27293D",

    fg="#F8FAFC"

).pack(

    pady=(15, 2)

)

tk.Label(

    input_frame,

    text=(

        "PCAP Forensic Analysis: Integrity Verification, ML Detection, Explainable AI, and Human Review"

    ),

    font=(

        "Segoe UI",

        9

    ),

    bg="#27293D",

    fg="#9CA3AF"

).pack(

    pady=(0, 10)

)

drop_area = tk.Label(

    input_frame,

    text="☁️ Drag & Drop PCAP / PCAPNG",

    bg="#1E1E2E",

    fg="#9CA3AF",

    font=(

        "Segoe UI",

        11

    ),

    width=35,

    height=4,

    highlightbackground="#4B5563",

    highlightthickness=1

)

drop_area.pack(

    pady=10,

    padx=20

)

drop_area.drop_target_register(

    DND_FILES

)

drop_area.dnd_bind(

    "<<Drop>>",

    pcap_drop_file

)

lbl_pcap_file = tk.Label(

    input_frame,

    text="No PCAP selected",

    font=(

        "Segoe UI",

        10

    ),

    bg="#27293D",

    fg="#6B7280"

)

lbl_pcap_file.pack(

    pady=(0, 10)

)

btn_analyze = tk.Button(

    input_frame,

    text="Analyze PCAP",

    font=(

        "Segoe UI",

        10,

        "bold"

    ),

    bg="#3B82F6",

    fg="white",

    relief="flat",

    padx=20,

    pady=8,

    command=analyze_trigger

)

btn_analyze.pack(

    pady=(5, 15)

)


# ============================================================
# DASHBOARD
# ============================================================

metrics_frame = tk.Frame(

    top_frame,

    bg="#1E1E2E"

)

metrics_frame.pack(

    side=tk.RIGHT,

    fill="both",

    expand=True

)


def create_metric_card(

    parent,

    title,

    value="0",

    color="#9CA3AF"

):

    card = tk.Frame(

        parent,

        bg="#27293D",

        highlightbackground="#374151",

        highlightthickness=1

    )

    tk.Label(

        card,

        text=title,

        font=(

            "Segoe UI",

            10

        ),

        bg="#27293D",

        fg="#9CA3AF"

    ).pack(

        pady=(15, 5)

    )

    val = tk.Label(

        card,

        text=value,

        font=(

            "Segoe UI",

            24,

            "bold"

        ),

        bg="#27293D",

        fg=color

    )

    val.pack(

        pady=(0, 15)

    )

    return (

        card,

        val

    )


card_total, lbl_val_total = create_metric_card(

    metrics_frame,

    "TOTAL FLOWS",

    color="#F8FAFC"

)

card_total.grid(

    row=0,

    column=0,

    sticky="nsew",

    padx=5,

    pady=5

)

card_benign, lbl_val_benign = create_metric_card(

    metrics_frame,

    "BENIGN AI FINDINGS",

    color="#10B981"

)

card_benign.grid(

    row=0,

    column=1,

    sticky="nsew",

    padx=5,

    pady=5

)

card_threat, lbl_val_threat = create_metric_card(

    metrics_frame,

    "THREAT AI FINDINGS",

    color="#9CA3AF"

)

card_threat.grid(

    row=1,

    column=0,

    columnspan=2,

    sticky="nsew",

    padx=5,

    pady=5

)

metrics_frame.grid_columnconfigure(

    0,

    weight=1

)

metrics_frame.grid_columnconfigure(

    1,

    weight=1

)


# ============================================================
# PIPELINE LOG
# ============================================================

terminal_frame = tk.Frame(

    tab_live,

    bg="#0F111A",

    highlightbackground="#374151",

    highlightthickness=1

)

terminal_frame.pack(

    fill="both",

    expand=True,

    pady=(10, 0)

)

log_console = tk.Text(

    terminal_frame,

    bg="#0F111A",

    fg="#A6ACCD",

    font=(

        "Consolas",

        10

    ),

    state=tk.DISABLED,

    padx=15,

    pady=15,

    relief="flat"

)

log_console.pack(

    fill="both",

    expand=True

)

log_console.tag_config(

    "info",

    foreground="#82AAFF"

)

log_console.tag_config(

    "success",

    foreground="#C3E88D"

)

log_console.tag_config(

    "error",

    foreground="#F07178"

)

write_log(

    "System initialized. "

    "Awaiting PCAP evidence..."

)


# ============================================================
# TAB 2 — SHAP + HUMAN REVIEW
# ============================================================

tab_xai = tk.Frame(

    notebook,

    bg="#1E1E2E"

)

notebook.add(

    tab_xai,

    text="SHAP & Human Review"

)

lbl_case_id = tk.Label(

    tab_xai,

    text="Case ID: Waiting for analysis",

    bg="#1E1E2E",

    fg="#F8FAFC",

    font=(

        "Segoe UI",

        11,

        "bold"

    )

)

lbl_case_id.pack(

    anchor="w",

    padx=15,

    pady=(10, 3)

)

lbl_hash = tk.Label(

    tab_xai,

    text="Evidence SHA-256: Not available",

    bg="#1E1E2E",

    fg="#9CA3AF",

    font=(

        "Consolas",

        9

    )

)

lbl_hash.pack(

    anchor="w",

    padx=15

)

lbl_xai_summary = tk.Label(

    tab_xai,

    text="No analysis available.",

    bg="#27293D",

    fg="#34D399",

    font=(

        "Segoe UI",

        11,

        "bold"

    )

)

lbl_xai_summary.pack(

    fill="x",

    padx=15,

    pady=10

)

tk.Label(

    tab_xai,

    text=(

        "SHAP Explanation: AI Feature Contributions"

    ),

    bg="#1E1E2E",

    fg="#F8FAFC",

    font=(

        "Segoe UI",

        10,

        "bold"

    )

).pack(

    anchor="w",

    padx=15

)

txt_xai = tk.Text(

    tab_xai,

    bg="#0F111A",

    fg="#A6ACCD",

    font=(

        "Consolas",

        9

    ),

    height=18,

    state=tk.DISABLED,

    relief="flat"

)

txt_xai.pack(

    fill="both",

    expand=True,

    padx=15,

    pady=5

)


# ============================================================
# HUMAN REVIEW
# ============================================================

review_frame = tk.Frame(

    tab_xai,

    bg="#27293D"

)

review_frame.pack(

    fill="x",

    padx=15,

    pady=10

)

tk.Label(

    review_frame,

    text="Investigator Decision:",

    bg="#27293D",

    fg="#F8FAFC",

    font=(

        "Segoe UI",

        10,

        "bold"

    )

).pack(

    side=tk.LEFT,

    padx=10

)

investigator_decision = ttk.Combobox(

    review_frame,

    values=[

        "Pending",

        "Accept AI Finding",

        "Reject AI Finding",

        "Modify AI Finding",

        "Insufficient Evidence"

    ],

    state="readonly",

    width=25

)

investigator_decision.set(

    "Pending"

)

investigator_decision.pack(

    side=tk.LEFT,

    padx=5,

    pady=10

)

tk.Label(

    review_frame,

    text="Investigator Comment:",

    bg="#27293D",

    fg="#F8FAFC",

    font=(

        "Segoe UI",

        10,

        "bold"

    )

).pack(

    side=tk.LEFT,

    padx=10

)

txt_investigator_comment = tk.Text(

    review_frame,

    height=3,

    width=40,

    bg="#0F111A",

    fg="#F8FAFC",

    relief="flat"

)

txt_investigator_comment.pack(

    side=tk.LEFT,

    padx=5,

    pady=5

)

tk.Button(

    review_frame,

    text="Save Review",

    bg="#10B981",

    fg="white",

    relief="flat",

    font=(

        "Segoe UI",

        9,

        "bold"

    ),

    command=save_investigator_review

).pack(

    side=tk.RIGHT,

    padx=10

)


# ============================================================
# TAB 3 — MODEL EVALUATION
# ============================================================

tab_eval = tk.Frame(

    notebook,

    bg="#1E1E2E"

)

notebook.add(

    tab_eval,

    text="Model Evaluation"

)

tk.Label(

    tab_eval,

    text=(

        "Validation Mode"
    ),

    bg="#1E1E2E",

    fg="#F8FAFC",

    font=(

        "Segoe UI",

        12,

        "bold"

    )

).pack(

    anchor="w",

    padx=15,

    pady=(10, 2)

)

tk.Label(

    tab_eval,

    text=(

        "This is separate from forensic PCAP analysis. "

        "A random PCAP has unknown ground truth and "

        "cannot be used to calculate confusion-matrix metrics."

    ),

    bg="#1E1E2E",

    fg="#9CA3AF",

    font=(

        "Segoe UI",

        9

    ),

    wraplength=900,

    justify="left"

).pack(

    anchor="w",

    padx=15,

    pady=(0, 10)

)

eval_header = tk.Frame(

    tab_eval,

    bg="#27293D",

    highlightbackground="#374151",

    highlightthickness=1

)

eval_header.pack(

    fill="x",

    pady=10

)

lbl_eval_drop = tk.Label(

    eval_header,

    text=(

        "☁️ Drop Labeled Validation/Test CSV "

        "(must contain label_binary)"

    ),

    bg="#1E1E2E",

    fg="#9CA3AF",

    font=(

        "Segoe UI",

        11

    ),

    height=2,

    highlightbackground="#4B5563",

    highlightthickness=1

)

lbl_eval_drop.pack(

    pady=10,

    padx=20,

    fill="x"

)

lbl_eval_drop.drop_target_register(

    DND_FILES

)

lbl_eval_drop.dnd_bind(

    "<<Drop>>",

    eval_drop_file

)

lbl_eval_file = tk.Label(

    eval_header,

    text=(

        "Waiting for labeled evaluation dataset..."

    ),

    font=(

        "Segoe UI",

        10,

        "italic"

    ),

    bg="#27293D",

    fg="#6B7280"

)

lbl_eval_file.pack(

    pady=(0, 10)

)

eval_body = tk.Frame(

    tab_eval,

    bg="#1E1E2E"

)

eval_body.pack(

    fill="both",

    expand=True

)

cm_frame = tk.Frame(

    eval_body,

    bg="#27293D",

    highlightbackground="#374151",

    highlightthickness=1,

    width=400

)

cm_frame.pack(

    side=tk.LEFT,

    fill="y",

    padx=(0, 10)

)

cm_frame.pack_propagate(

    False

)

stats_frame = tk.Frame(

    eval_body,

    bg="#1E1E2E"

)

stats_frame.pack(

    side=tk.RIGHT,

    fill="both",

    expand=True

)


def make_stat_row(

    parent,

    title1,

    title2

):

    f = tk.Frame(

        parent,

        bg="#1E1E2E"

    )

    f.pack(

        fill="x",

        pady=2

    )

    t1 = tk.Label(

        f,

        text=title1,

        font=(

            "Segoe UI",

            10,

            "bold"

        ),

        bg="#1E1E2E",

        fg="#9CA3AF",

        width=15,

        anchor="w"

    )

    t1.pack(

        side=tk.LEFT,

        padx=10

    )

    v1 = tk.Label(

        f,

        text="-",

        font=(

            "Segoe UI",

            11

        ),

        bg="#1E1E2E",

        fg="#34D399",

        width=10,

        anchor="w"

    )

    v1.pack(

        side=tk.LEFT

    )

    t2 = tk.Label(

        f,

        text=title2,

        font=(

            "Segoe UI",

            10,

            "bold"

        ),

        bg="#1E1E2E",

        fg="#9CA3AF",

        width=15,

        anchor="w"

    )

    t2.pack(

        side=tk.LEFT,

        padx=10

    )

    v2 = tk.Label(

        f,

        text="-",

        font=(

            "Segoe UI",

            11

        ),

        bg="#1E1E2E",

        fg="#34D399",

        width=10,

        anchor="w"

    )

    v2.pack(

        side=tk.LEFT

    )

    return (

        v1,

        v2

    )


lbl_acc, lbl_prec = make_stat_row(

    stats_frame,

    "Accuracy:",

    "Precision:"

)

lbl_rec, lbl_spec = make_stat_row(

    stats_frame,

    "Recall / TPR:",

    "Specificity / TNR:"

)

lbl_f1, lbl_macro = make_stat_row(

    stats_frame,

    "F1 Score:",

    "Macro F1:"

)

lbl_roc, lbl_pr = make_stat_row(

    stats_frame,

    "ROC-AUC:",

    "PR-AUC:"

)

lbl_fpr, lbl_fnr = make_stat_row(

    stats_frame,

    "False Pos (FPR):",

    "False Neg (FNR):"

)

lbl_weight, _ = make_stat_row(

    stats_frame,

    "Weighted F1:",

    ""

)

tk.Label(

    stats_frame,

    text="Per-Class Performance Report",

    font=(

        "Segoe UI",

        10,

        "bold"

    ),

    bg="#1E1E2E",

    fg="#F8FAFC"

).pack(

    anchor="w",

    padx=10,

    pady=(20, 5)

)

txt_report = tk.Text(

    stats_frame,

    bg="#0F111A",

    fg="#A6ACCD",

    font=(

        "Consolas",

        9

    ),

    height=8,

    state=tk.DISABLED,

    relief="flat",

    padx=10,

    pady=10

)

txt_report.pack(

    fill="x",

    padx=10

)


# ============================================================
# START APPLICATION
# ============================================================

root.mainloop()