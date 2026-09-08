import os
import glob
import json
import shutil
import subprocess
from datetime import datetime, timezone

import numpy as np
import pandas as pd

from services.config import (
    CICFLOWMETER_JAR,
    CICFLOWMETER_JAVA,
    CICFLOWMETER_NATIVE_DIR,
    CICFLOWMETER_EXECUTABLE,
    FLOW_ENGINE,
)
from services import pyflow_extractor


# ============================================================
# SUPPORTED CAPTURE FILES
# ============================================================

SUPPORTED_PCAP_EXTENSIONS = (
    ".pcap",
    ".pcapng",
)


def validate_pcap_file(pcap_path):
    """
    Validate that the supplied evidence is a supported
    PCAP / PCAPNG file.
    """

    if not pcap_path:
        raise ValueError(
            "No PCAP file was supplied."
        )

    if not os.path.isfile(pcap_path):
        raise FileNotFoundError(
            f"PCAP file does not exist:\n{pcap_path}"
        )

    extension = os.path.splitext(
        pcap_path
    )[1].lower()

    if extension not in SUPPORTED_PCAP_EXTENSIONS:
        raise ValueError(
            "Unsupported capture format.\n\n"
            "ForenXAI accepts:\n"
            "  .pcap\n"
            "  .pcapng"
        )

    if os.path.getsize(pcap_path) == 0:
        raise ValueError(
            "The supplied PCAP file is empty."
        )


# ============================================================
# CICFLOWMETER COMMAND
# ============================================================

def _build_cicflowmeter_command(
    pcap_path,
    output_dir
):
    """
    Build the CICFlowMeter v4 command.

    Priority:

    1. CICFLOWMETER_EXECUTABLE
    2. CICFLOWMETER_JAR

    For the official CICFlowMeter v4 command class,
    the expected arguments are:

        <input-pcap> <output-directory>
    """

    # --------------------------------------------------------
    # Direct executable / BAT / CMD
    # --------------------------------------------------------

    if CICFLOWMETER_EXECUTABLE:

        executable = os.path.abspath(
            os.path.expandvars(
                os.path.expanduser(
                    CICFLOWMETER_EXECUTABLE
                )
            )
        )

        if not os.path.exists(executable):
            raise FileNotFoundError(
                "CICFlowMeter executable was configured but "
                "could not be found:\n\n"
                f"{executable}"
            )

        extension = os.path.splitext(
            executable
        )[1].lower()

        # --------------------------------------------------------
        # CICFlowMeter v4 expects an INPUT DIRECTORY
        # --------------------------------------------------------

        if extension in (".bat", ".cmd"):

            input_directory = os.path.dirname(
                os.path.abspath(pcap_path)
            )

            return [
                "cmd",
                "/c",
                executable,
                input_directory,
                output_dir,
            ]

        return [
            executable,
            pcap_path,
            output_dir,
        ]

    # --------------------------------------------------------
    # JAR
    # --------------------------------------------------------

    if CICFLOWMETER_JAR:

        jar_path = os.path.abspath(
            os.path.expandvars(
                os.path.expanduser(
                    CICFLOWMETER_JAR
                )
            )
        )

        if not os.path.isfile(jar_path):
            raise FileNotFoundError(
                "CICFlowMeter JAR was configured but "
                "could not be found:\n\n"
                f"{jar_path}"
            )

        command = [
            CICFLOWMETER_JAVA,
        ]

        # jNetPcap native library directory
        if CICFLOWMETER_NATIVE_DIR:

            native_dir = os.path.abspath(
                os.path.expandvars(
                    os.path.expanduser(
                        CICFLOWMETER_NATIVE_DIR
                    )
                )
            )

            if not os.path.isdir(native_dir):
                raise FileNotFoundError(
                    "CICFlowMeter native jNetPcap directory "
                    "does not exist:\n\n"
                    f"{native_dir}"
                )

            command.extend([
                f"-Djava.library.path={native_dir}"
            ])

        command.extend([
            "-jar",
            jar_path,
            pcap_path,
            output_dir,
        ])

        return command

    raise RuntimeError(
        "CICFlowMeter v4 is not configured.\n\n"
        "Configure either:\n"
        "  CICFLOWMETER_EXECUTABLE\n"
        "or:\n"
        "  CICFLOWMETER_JAR\n\n"
        "Example:\n"
        "  CICFLOWMETER_JAR=C:\\\\Tools\\\\CICFlowMeter\\\\CICFlowMeter-4.0.jar"
    )


# ============================================================
# OUTPUT FILE DISCOVERY
# ============================================================

def _find_generated_csv(
    pcap_path,
    output_dir
):
    """
    Locate the CSV generated by CICFlowMeter.

    Official CICFlowMeter v4 uses:

        <pcap filename>_Flow.csv
    """

    base_name = os.path.basename(
        pcap_path
    )

    expected_path = os.path.join(
        output_dir,
        f"{base_name}_Flow.csv"
    )

    if os.path.isfile(expected_path):
        return expected_path

    # Some CICFlowMeter builds may remove the original
    # extension before constructing the output filename.
    stem = os.path.splitext(
        base_name
    )[0]

    alternative_paths = [
        os.path.join(
            output_dir,
            f"{stem}_Flow.csv"
        ),
        os.path.join(
            output_dir,
            f"{base_name}_ISCX.csv"
        ),
        os.path.join(
            output_dir,
            f"{stem}_ISCX.csv"
        ),
    ]

    for path in alternative_paths:
        if os.path.isfile(path):
            return path

    # Final fallback: search for generated CSV files.
    csv_files = glob.glob(
        os.path.join(
            output_dir,
            "*.csv"
        )
    )

    if len(csv_files) == 1:
        return csv_files[0]

    if not csv_files:
        raise FileNotFoundError(
            "CICFlowMeter completed but did not "
            "generate a CSV flow file.\n\n"
            f"Expected output directory:\n{output_dir}"
        )

    raise FileNotFoundError(
        "CICFlowMeter generated CSV files, but "
        "ForenXAI could not uniquely identify the "
        "correct output file.\n\n"
        "Generated files:\n"
        + "\n".join(csv_files)
    )


# ============================================================
# RUN CICFLOWMETER
# ============================================================
def _get_cicflowmeter_working_directory(command):
    """
    Determine the correct working directory for CICFlowMeter.

    For cfm.bat, the working directory must be the CICFlowMeter
    bin directory because cfm.bat uses:

        -Djava.library.path=../lib/native
    """

    if not command:
        return None

    executable = command[2] if (
        len(command) >= 3
        and command[0].lower() == "cmd"
        and command[1].lower() == "/c"
    ) else command[0]

    executable_ext = os.path.splitext(
        executable
    )[1].lower()

    if executable_ext in (".bat", ".cmd"):
        return os.path.dirname(
            os.path.abspath(executable)
        )

    return None

def run_cicflowmeter(
    pcap_path,
    output_dir,
    log_fn=None
):
    """
    Run CICFlowMeter v4 against a single PCAP / PCAPNG.

    Returns:
        generated_csv_path
    """

    validate_pcap_file(
        pcap_path
    )

    os.makedirs(
        output_dir,
        exist_ok=True
    )

    command = _build_cicflowmeter_command(
        pcap_path,
        output_dir
    )

    if log_fn:
        log_fn(
            "[+] CICFlowMeter command prepared.",
            "success"
        )

        log_fn(
            "[+] Input capture: "
            + os.path.basename(pcap_path),
            "info"
        )

        log_fn(
            "[+] Flow output directory: "
            + output_dir,
            "info"
        )

    try:

        working_directory = _get_cicflowmeter_working_directory(
            command
        )

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            cwd=working_directory,
            check=False,
        )

    except FileNotFoundError as exc:

        raise RuntimeError(
            "Unable to start CICFlowMeter.\n\n"
            "Make sure Java/CICFlowMeter is installed "
            "and configured correctly.\n\n"
            f"Command:\n{' '.join(command)}"
        ) from exc

    if result.stdout and log_fn:

        for line in result.stdout.splitlines():

            line = line.strip()

            if line:
                log_fn(
                    "[CICFlowMeter] " + line,
                    "info"
                )

    if result.stderr and log_fn:

        for line in result.stderr.splitlines():

            line = line.strip()

            if line:
                log_fn(
                    "[CICFlowMeter] " + line,
                    "info"
                )

    if result.returncode != 0:

        error_output = (
            result.stderr.strip()
            or result.stdout.strip()
            or "No diagnostic output was provided."
        )

        raise RuntimeError(
            "CICFlowMeter execution failed.\n\n"
            f"Exit code: {result.returncode}\n\n"
            f"{error_output}"
        )

    generated_csv = _find_generated_csv(
        pcap_path,
        output_dir
    )

    if log_fn:
        log_fn(
            "[+] CICFlowMeter generated flow CSV: "
            + generated_csv,
            "success"
        )

    return generated_csv


# ============================================================
# LOAD CICFLOWMETER CSV
# ============================================================

def load_cicflowmeter_csv(
    csv_path
):
    """
    Load a CICFlowMeter-generated CSV into a DataFrame.
    """

    if not os.path.isfile(csv_path):
        raise FileNotFoundError(
            f"CICFlowMeter CSV does not exist:\n{csv_path}"
        )

    df = pd.read_csv(
        csv_path,
        low_memory=False
    )

    if df.empty:
        return df

    # CICFlowMeter datasets can contain leading/trailing
    # whitespace in column names depending on the version
    # or source dataset.
    df.columns = [
        str(column).strip()
        for column in df.columns
    ]

    return df

# ============================================================
# FEATURE NAME NORMALIZATION
# ============================================================

def normalize_feature_names(df):
    """
    Normalize CICFlowMeter v4 feature names into the feature
    naming convention used by the frozen ForenXAI model schemas.

    IMPORTANT:
        This changes column names only.
        It does NOT change feature values.

    Examples:

        Destination Port
            -> Dst Port

        Total Backward Packets
            -> Total Bwd packets

        Total Length of Bwd Packets
            -> Total Length of Bwd Packet

        Fwd Init Win bytes
            -> FWD Init Win Bytes
    """

    df = df.copy()

    # --------------------------------------------------------
    # Explicit aliases
    # --------------------------------------------------------

    aliases = {

        # ----------------------------------------------------
        # Ports / protocol
        # ----------------------------------------------------

        "Destination Port":
            "Dst Port",

        "Dst Port":
            "Dst Port",

        "Protocol":
            "Protocol",

        # ----------------------------------------------------
        # Packet counts
        # ----------------------------------------------------

        "Total Fwd Packets":
            "Total Fwd Packet",

        "Total Fwd Packet":
            "Total Fwd Packet",

        "Total Backward Packets":
            "Total Bwd packets",

        "Total Bwd Packets":
            "Total Bwd packets",

        "Total Bwd packets":
            "Total Bwd packets",

        # ----------------------------------------------------
        # Packet lengths
        # ----------------------------------------------------

        "Total Length of Fwd Packets":
            "Total Length of Fwd Packet",

        "Total Length of Fwd Packet":
            "Total Length of Fwd Packet",

        "Total Length of Bwd Packets":
            "Total Length of Bwd Packet",

        "Total Length of Bwd Packet":
            "Total Length of Bwd Packet",

        # ----------------------------------------------------
        # Initial TCP window
        # ----------------------------------------------------

        "Fwd Init Win bytes":
            "FWD Init Win Bytes",

        "Fwd Init Win Bytes":
            "FWD Init Win Bytes",

        "FWD Init Win Bytes":
            "FWD Init Win Bytes",

        "Bwd Init Win bytes":
            "Bwd Init Win Bytes",

        "Bwd Init Win Bytes":
            "Bwd Init Win Bytes",

        # ----------------------------------------------------
        # Subflow
        # ----------------------------------------------------

        "Subflow Bwd Bytes":
            "Subflow Bwd Bytes",

        # ----------------------------------------------------
        # Common CICFlowMeter naming variants
        # ----------------------------------------------------

        "Flow IAT Mean":
            "Flow IAT Mean",

        "Flow IAT Std":
            "Flow IAT Std",

        "Flow IAT Max":
            "Flow IAT Max",

        "Flow IAT Min":
            "Flow IAT Min",

        "Flow Packets/s":
            "Flow Packets/s",

        "Average Packet Size":
            "Average Packet Size",

        "Bwd Header Length":
            "Bwd Header Length",

        "Fwd Header Length":
            "Fwd Header Length",

        "Fwd Packet Length Min":
            "Fwd Packet Length Min",

        "Fwd Packet Length Std":
            "Fwd Packet Length Std",

        "Bwd Packet Length Mean":
            "Bwd Packet Length Mean",

        "Bwd Packet Length Max":
            "Bwd Packet Length Max",

        "Bwd Packet Length Std":
            "Bwd Packet Length Std",

        "FIN Flag Count":
            "FIN Flag Count",

        "SYN Flag Count":
            "SYN Flag Count",

        "PSH Flag Count":
            "PSH Flag Count",

        "ACK Flag Count":
            "ACK Flag Count",

        "Flow Duration":
            "Flow Duration",
    }

    renamed_columns = {}

    for column in df.columns:

        clean_name = str(
            column
        ).strip()

        if clean_name in aliases:

            canonical_name = aliases[
                clean_name
            ]

            if clean_name != canonical_name:

                renamed_columns[
                    clean_name
                ] = canonical_name

    if renamed_columns:

        df.rename(
            columns=renamed_columns,
            inplace=True
        )

    return df


# ============================================================
# DATA CLEANING
# ============================================================

def clean_features(df):
    """
    Clean and normalize CICFlowMeter v4 feature data.

    Feature names are normalized into the naming convention
    used by the frozen ForenXAI model schemas.
    """

    df = normalize_feature_names(
        df
    )

    # --------------------------------------------------------
    # Remove accidental whitespace from column names
    # --------------------------------------------------------

    df.columns = [
        str(column).strip()
        for column in df.columns
    ]

    # --------------------------------------------------------
    # Replace CICFlowMeter invalid numeric values
    # --------------------------------------------------------

    df.replace(
        [np.inf, -np.inf],
        np.nan,
        inplace=True
    )

    # --------------------------------------------------------
    # Convert object columns to numeric when possible
    # --------------------------------------------------------

    for column in df.columns:

        if df[column].dtype == "object":

            converted = pd.to_numeric(
                df[column],
                errors="coerce"
            )

            # Only replace the original column if the
            # conversion actually produced numeric values.
            if converted.notna().sum() > 0:
                df[column] = converted

    # --------------------------------------------------------
    # Fill numeric missing values
    # --------------------------------------------------------

    numeric_columns = df.select_dtypes(
        include=[np.number]
    ).columns

    for column in numeric_columns:

        df[column] = df[column].fillna(0)

    return df


# ============================================================
# ENGINE SELECTION
# ============================================================

def java_engine_status():
    """
    Report whether CICFlowMeter v4 can actually be run.

    Returns a dict rather than a bare bool because when the answer is "no"
    the investigator needs to know which piece is missing, not just that
    something is.
    """

    paths = {
        "executable": CICFLOWMETER_EXECUTABLE,
        "jar": CICFLOWMETER_JAR,
        "native_dir": CICFLOWMETER_NATIVE_DIR,
    }

    found = {}
    for name, value in paths.items():
        if not value:
            found[name] = None
            continue
        resolved = os.path.abspath(
            os.path.expandvars(os.path.expanduser(value))
        )
        found[name] = resolved if os.path.exists(resolved) else None

    java = shutil.which(CICFLOWMETER_JAVA) if CICFLOWMETER_JAVA else None

    # The launcher alone is enough; the jar route additionally needs the
    # jnetpcap natives and a java on PATH.
    can_run = bool(
        found["executable"]
        or (found["jar"] and found["native_dir"] and java)
    )

    missing = [name for name, value in found.items() if value is None]
    if not java:
        missing.append("java (not on PATH)")

    return {
        "available": can_run,
        "found": found,
        "java": java,
        "missing": missing,
    }


def select_engine(log_fn=None):
    """
    Decide which flow extractor to use, and say so.

    Honours config.FLOW_ENGINE. In "auto" the Java tool wins when present,
    because it is the reference implementation the model was trained
    against; the Python extractor is the fallback that keeps the tool
    usable when it is not.
    """

    status = java_engine_status()

    if FLOW_ENGINE == "java":
        if not status["available"]:
            raise RuntimeError(
                "FLOW_ENGINE is set to 'java' but CICFlowMeter v4 is not "
                "usable.\n\n"
                "Missing: " + ", ".join(status["missing"]) + "\n\n"
                "Either install CICFlowMeter v4 at the path in "
                "services/config.py, or set FLOW_ENGINE to 'auto'."
            )
        return "java"

    if FLOW_ENGINE == "python":
        return "python"

    # auto
    if status["available"]:
        return "java"

    if not pyflow_extractor.AVAILABLE:
        raise RuntimeError(
            "No flow extraction engine is available.\n\n"
            "CICFlowMeter v4 is missing: "
            + ", ".join(status["missing"]) + "\n\n"
            "The Python fallback is also unavailable: "
            f"{pyflow_extractor.IMPORT_ERROR}\n\n"
            "Install the fallback with:\n"
            "    pip install cicflowmeter scapy"
        )

    if log_fn:
        log_fn(
            "[!] CICFlowMeter v4 was not found ("
            + ", ".join(status["missing"])
            + ").",
            "warning",
        )
        log_fn(
            "[!] Falling back to the Python flow extractor. It produces "
            "the same 74 features, but activity, bulk and subflow columns "
            "differ slightly from CICFlowMeter v4; the engine used is "
            "recorded with the case.",
            "warning",
        )

    return "python"


# ============================================================
# PROVENANCE RECORD
# ============================================================

def _write_extraction_record(case_dir, pcap_path, csv_path, engine, rows):
    """
    Write flow_extraction.json beside the flow CSV.

    Which engine produced a flow table is part of the evidence chain: two
    engines segment flows differently, so a feature value is only
    interpretable against the engine that computed it.
    """

    record = {
        "capture": os.path.abspath(pcap_path),
        "capture_bytes": os.path.getsize(pcap_path),
        "flow_csv": os.path.abspath(csv_path),
        "flows": rows,
        "engine": engine,
        "engine_detail": (
            "CICFlowMeter v4 (Java)"
            if engine == "java"
            else "Python fallback (scapy + cicflowmeter port)"
        ),
        "flow_timeout_seconds": (
            120 if engine == "java"
            else pyflow_extractor.FLOW_TIMEOUT_SECONDS
        ),
        "extracted_utc": datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        ),
    }

    path = os.path.join(case_dir, "flow_extraction.json")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=2)
    except OSError:
        # A missing provenance file must not lose the analysis; the same
        # facts still travel on df.attrs.
        pass

    return record


# ============================================================
# COMPLETE EXTRACTION
# ============================================================

def extract_flows_from_pcap(
    pcap_path,
    case_dir,
    log_fn=None
):
    """
    Complete PCAP -> flow CSV -> DataFrame operation.

    Uses CICFlowMeter v4 when it is installed, and the pure-Python
    extractor when it is not. See services/config.py FLOW_ENGINE.

    Returns:

        df,
        generated_csv_path

    The engine that produced the table is on df.attrs["flow_engine"] and in
    flow_extraction.json inside case_dir.
    """

    validate_pcap_file(pcap_path)

    os.makedirs(case_dir, exist_ok=True)

    engine = select_engine(log_fn=log_fn)

    if engine == "java":
        csv_path = run_cicflowmeter(
            pcap_path=pcap_path,
            output_dir=case_dir,
            log_fn=log_fn,
        )
    else:
        base = os.path.splitext(os.path.basename(pcap_path))[0]
        csv_path = os.path.join(case_dir, base + "_Flow.csv")
        pyflow_extractor.extract(
            pcap_path=pcap_path,
            output_csv=csv_path,
            log_fn=log_fn,
        )

    df = load_cicflowmeter_csv(csv_path)

    if df.empty:
        raise ValueError(
            "Flow extraction produced an empty CSV. "
            "No network flows were extracted from the "
            "supplied PCAP."
        )

    record = _write_extraction_record(
        case_dir, pcap_path, csv_path, engine, len(df)
    )

    df.attrs["flow_engine"] = engine
    df.attrs["flow_extraction"] = record

    return df, csv_path