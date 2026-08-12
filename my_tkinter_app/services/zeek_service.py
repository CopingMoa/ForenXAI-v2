import numpy as np
import pandas as pd


# ============================================================
# ZEEK FEATURE EXTRACTION
# ============================================================

def parse_zeek_conn_log(log_path):
    with open(log_path, "r", errors="replace") as f:
        lines = f.readlines()

    fields_line = next(
        (line for line in lines if line.startswith("#fields")),
        None
    )

    if fields_line is None:
        raise ValueError(
            "Zeek conn.log does not contain a #fields definition."
        )

    columns = fields_line.strip().split("\t")[1:]

    data_rows = [
        line.strip().split("\t")
        for line in lines
        if not line.startswith("#") and line.strip()
    ]

    if not data_rows:
        return pd.DataFrame(columns=columns)

    df = pd.DataFrame(data_rows, columns=columns)

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
    df.replace("-", np.nan, inplace=True)

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
            df[col] = pd.to_numeric(df[col], errors="coerce")

    return df


# ============================================================
# DATA CLEANING
# ============================================================

def clean_features(df):
    df = df.copy()

    # Replace infinite values
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Convert object columns where possible
    for col in df.columns:
        if df[col].dtype == "object":
            converted = pd.to_numeric(df[col], errors="coerce")

            # Only replace if meaningful numeric conversion exists
            if converted.notna().sum() > 0:
                df[col] = converted

    # Fill numerical missing values
    numeric_cols = df.select_dtypes(include=[np.number]).columns

    for col in numeric_cols:
        df[col] = df[col].fillna(0)

    return df
