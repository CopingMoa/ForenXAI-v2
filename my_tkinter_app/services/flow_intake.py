"""
flow_intake.py
==============

Reads a CICFlowMeter CSV that came from an uploaded capture, and refuses it
clearly when it cannot be trusted.

WHY THIS IS SEPARATE
Everything downstream -- prediction, SHAP, recommendations -- assumes 74
named numeric columns in a fixed order. A file that arrives from outside is
the one place those assumptions can break, and breaking them silently is
worse than failing: the model will happily return confident predictions from
a table whose columns mean something else.

WHAT IS CHECKED, AND WHY EACH ONE

  path         a real regular file, not a directory, device or dangling
               symlink. Reading a Windows device path (CON, NUL, COM1) hangs
               the interface with no error.
  size         a cap, because a multi-gigabyte CSV read into a DataFrame
               exhausts memory and takes the whole application with it.
  rows         a cap with a clear message, so a 20-million-row capture is
               refused rather than freezing for ten minutes.
  columns      normalised for the CWE/CWR spelling and whitespace that vary
               between CICFlowMeter builds, then matched by NAME. Never by
               position -- two of the training datasets share column names in
               a different order, and matching by position silently puts
               backward byte counts into a forward byte column.
  coercion     non-numeric cells become 0, which is correct at inference, but
               the COUNT is reported. A file that is 40% unparseable is not a
               flow table and the investigator needs to know.
  emptiness    a header-only file produces an empty matrix and every
               downstream argmax raises. Refused up front.

WHAT IS NOT A THREAT HERE
CSV formula injection is a spreadsheet problem; nothing in this application
writes the values back to a spreadsheet or evaluates them. Values are coerced
to float and anything that fails becomes 0.
"""

import os
import re
import stat

import numpy as np
import pandas as pd


# ============================================================
# LIMITS
#
# Generous enough for a real capture, small enough that a hostile or
# corrupt file cannot take the interface down. Raise them deliberately
# rather than removing the check.
# ============================================================

MAX_FILE_BYTES = 2 * 1024 ** 3          # 2 GiB on disk
MAX_ROWS = 2_000_000                     # about 1 GB in memory at 74 float32
MAX_COERCION_SHARE = 0.25                # refuse if over a quarter unparseable

# Windows reserved device names. Opening one blocks forever.
_RESERVED = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}


class IntakeError(Exception):
    """A file that cannot be trusted. The message is shown to the user."""


# ============================================================
# COLUMN NORMALISATION
# ============================================================

# CICFlowMeter builds disagree on spelling. The real TCP flag is CWR
# (Congestion Window Reduced); CWE is a long-standing typo in several
# exports. Both fold to the name the model was trained on.
_RENAMES = {
    "cwe flag count": "CWR Flag Count",
    "cwr flag cnt": "CWR Flag Count",
    "cwr flag count": "CWR Flag Count",
}


def _canonical(name):
    """Strip whitespace and BOM, collapse inner spaces, apply known renames."""
    clean = re.sub(r"\s+", " ", str(name).replace("﻿", "")).strip()
    return _RENAMES.get(clean.lower(), clean)


def normalise_columns(df):
    """
    Canonicalise column names and drop duplicates created by renaming.

    Some exports carry both "CWE Flag Count" and "CWR Flag Cnt". After
    renaming both become the same name; the first is kept because it sits in
    its original position and the appended one has less certain provenance.
    """
    df = df.copy()
    df.columns = [_canonical(c) for c in df.columns]
    return df.loc[:, ~df.columns.duplicated(keep="first")]


# ============================================================
# PATH AND SIZE CHECKS
# ============================================================

def check_path(path):
    """Raise IntakeError unless this is a readable regular file."""

    if not path:
        raise IntakeError("No flow table was supplied.")

    stem = os.path.splitext(os.path.basename(path))[0].lower()
    if stem in _RESERVED:
        raise IntakeError(
            f"{os.path.basename(path)!r} is a reserved device name. "
            f"Rename the file and try again."
        )

    if not os.path.exists(path):
        raise IntakeError(f"No such file: {path}")

    try:
        info = os.stat(path)
    except OSError as e:
        raise IntakeError(f"Cannot read {os.path.basename(path)}: {e}")

    if not stat.S_ISREG(info.st_mode):
        raise IntakeError(
            f"{os.path.basename(path)} is not a regular file. Only a "
            f"CICFlowMeter CSV can be analysed."
        )

    if info.st_size == 0:
        raise IntakeError(f"{os.path.basename(path)} is empty.")

    if info.st_size > MAX_FILE_BYTES:
        raise IntakeError(
            f"{os.path.basename(path)} is "
            f"{info.st_size / 1024**3:.1f} GB, over the "
            f"{MAX_FILE_BYTES / 1024**3:.0f} GB limit. Split the capture "
            f"and analyse it in parts."
        )

    return info.st_size


# ============================================================
# READING
# ============================================================

def read_flows(path, required_features, max_rows=MAX_ROWS):
    """
    Read and validate a CICFlowMeter CSV.

    Returns (dataframe, report). The report is shown to the investigator, so
    every number in it is something they can act on.

    Raises IntakeError with a message fit for a dialog box.
    """

    size = check_path(path)

    try:
        # low_memory=False keeps pandas from inferring different dtypes for
        # different chunks of the same column, which produces object columns
        # that silently fail to scale.
        df = pd.read_csv(path, low_memory=False, nrows=max_rows + 1)
    except UnicodeDecodeError:
        raise IntakeError(
            f"{os.path.basename(path)} is not text. A PCAP must be converted "
            f"to a flow CSV by CICFlowMeter before it can be analysed."
        )
    except pd.errors.EmptyDataError:
        raise IntakeError(f"{os.path.basename(path)} has no readable rows.")
    except pd.errors.ParserError as e:
        raise IntakeError(f"{os.path.basename(path)} is not valid CSV: {e}")
    except MemoryError:
        raise IntakeError(
            f"{os.path.basename(path)} does not fit in memory. Split the "
            f"capture and analyse it in parts."
        )

    truncated = len(df) > max_rows
    if truncated:
        df = df.iloc[:max_rows]

    if df.empty:
        raise IntakeError(
            f"{os.path.basename(path)} contains headers but no flows."
        )

    df = normalise_columns(df)

    missing = [f for f in required_features if f not in df.columns]
    if missing:
        raise IntakeError(
            f"The flow table is missing {len(missing)} of the "
            f"{len(required_features)} features the model needs.\n\n"
            f"First few: {', '.join(missing[:6])}\n\n"
            f"This usually means the CSV came from a different "
            f"CICFlowMeter version, or is not a flow table at all."
        )

    report = {
        "file": os.path.basename(path),
        "bytes": size,
        "rows": int(len(df)),
        "columns": int(df.shape[1]),
        "truncated": truncated,
        "max_rows": max_rows,
        "extra_columns": [c for c in df.columns
                          if c not in required_features][:10],
    }

    return df, report


# ============================================================
# NUMERIC PREPARATION
# ============================================================

def to_matrix(df, required_features):
    """
    Select the model's features, in the model's order, as float32.

    Returns (values, report). Coercion is counted rather than hidden:
    infinities are real (rate columns divide by zero when duration is zero)
    but a large share of unparseable text means the file is not what it
    claims to be.
    """

    X = df[required_features].apply(pd.to_numeric, errors="coerce")

    total = X.size
    coerced = int(X.isna().sum().sum())
    infinite = int(np.isinf(X.to_numpy(dtype="float64",
                                       na_value=0.0)).sum())

    if total and coerced / total > MAX_COERCION_SHARE:
        raise IntakeError(
            f"{coerced:,} of {total:,} values ({coerced / total:.0%}) could "
            f"not be read as numbers. This is not a flow table, or the "
            f"columns do not line up with their headers."
        )

    # Filling with 0 rather than dropping the row is deliberate: at
    # inference a forensic tool cannot discard flows an investigator may
    # need to see, and training applied the same rule.
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0)

    report = {
        "cells": int(total),
        "coerced_to_zero": coerced,
        "coerced_share": round(coerced / total, 4) if total else 0.0,
        "infinite_replaced": infinite,
    }

    return X.astype("float32").values, report


def describe(report, matrix_report):
    """One line per fact, for the summary panel."""
    lines = [
        f"{report['rows']:,} flows read from {report['file']} "
        f"({report['bytes'] / 1e6:,.1f} MB, {report['columns']} columns)."
    ]
    if report["truncated"]:
        lines.append(
            f"Only the first {report['max_rows']:,} flows were analysed; "
            f"the file holds more."
        )
    if matrix_report["coerced_to_zero"]:
        lines.append(
            f"{matrix_report['coerced_to_zero']:,} values "
            f"({matrix_report['coerced_share']:.2%}) were not numeric and "
            f"were read as zero."
        )
    if matrix_report["infinite_replaced"]:
        lines.append(
            f"{matrix_report['infinite_replaced']:,} infinite values were "
            f"replaced with zero (rate columns divide by zero when a flow "
            f"has no duration)."
        )
    return lines


# ============================================================
# IDENTITY COLUMNS
#
# CICFlowMeter writes 79 columns; the model uses 74. The five it does not
# use are exactly the ones a forensic summary needs -- who talked to whom,
# and when. They are correctly excluded from the MODEL (an address is an
# identifier, not behaviour, and training on it memorises the lab) but
# throwing them away in the interface loses the first question an
# investigator asks.
#
# Every one is optional. A flow table without them still analyses; the
# panel simply reports less.
# ============================================================

IDENTITY = ["Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol",
            "Timestamp"]


def identity_columns(df):
    """Which identity columns this file actually carries."""
    return [c for c in IDENTITY if c in df.columns]


def capture_window(df):
    """
    Real capture span from the Timestamp column.

    This is what "how long was the capture" means. Summing flow durations
    does NOT answer it -- flows overlap in time, so the sum counts the same
    seconds many times over and reads as days for a capture of minutes.

    Returns None when there is no usable Timestamp.
    """
    if "Timestamp" not in df.columns:
        return None

    # CICFlowMeter v4 writes dd/mm/yyyy hh:mm:ss AM/PM. Parsing that as
    # month-first silently relabels 08/09 as 9 August instead of 8 September
    # -- the span stays roughly right, the DATE in the report does not, and a
    # wrong date in a forensic report is worse than no date.
    ts = pd.to_datetime(df["Timestamp"], errors="coerce",
                        format="mixed", dayfirst=True)

    # Fall back to month-first only if day-first parsed almost nothing, so a
    # US-formatted export is still read rather than reported as unusable.
    if ts.notna().sum() < 0.5 * len(df):
        alt = pd.to_datetime(df["Timestamp"], errors="coerce",
                             format="mixed", dayfirst=False)
        if alt.notna().sum() > ts.notna().sum():
            ts = alt

    ts = ts.dropna()

    if ts.empty:
        return None

    first, last = ts.min(), ts.max()
    seconds = float((last - first).total_seconds())

    return {
        "first_flow": first.isoformat(sep=" ", timespec="seconds"),
        "last_flow": last.isoformat(sep=" ", timespec="seconds"),
        "span_seconds": round(seconds, 1),
        "span_human": _human_span(seconds),
        "unparsed_timestamps": int(len(df) - len(ts)),
    }


def _human_span(seconds):
    if seconds < 60:
        return f"{seconds:.0f} s"
    if seconds < 3600:
        return f"{int(seconds // 60)} min {int(seconds % 60)} s"
    return f"{int(seconds // 3600)} h {int((seconds % 3600) // 60)} min"


def endpoints(df, mask=None, top=5):
    """
    Busiest sources and targets, optionally within one finding.

    `mask` is a boolean array selecting the flows of a single class, so the
    same function answers "who is in this capture" and "who is in this
    finding".
    """
    sub = df if mask is None else df[mask]
    out = {}

    for role, column in (("sources", "Src IP"), ("targets", "Dst IP")):
        if column in sub.columns and len(sub):
            counts = sub[column].astype(str).value_counts().head(top)
            out[role] = [{"address": a, "flows": int(n)}
                         for a, n in counts.items()]

    if "Dst Port" in sub.columns and len(sub):
        counts = pd.to_numeric(sub["Dst Port"], errors="coerce")                    .dropna().astype(int).value_counts().head(top)
        out["ports"] = [{"port": int(p), "flows": int(n)}
                        for p, n in counts.items()]

    return out
