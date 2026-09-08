import os


# ============================================================
# BASE DIRECTORY
# ============================================================

# my_tkinter_app/
BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)


# ============================================================
# MODEL
# ============================================================

MODEL_PATH = os.path.join(
    BASE_DIR,
    "models",
    "rf.pkl"
)


# ============================================================
# CASE OUTPUT
# ============================================================

CASE_OUTPUT_DIR = os.path.join(
    BASE_DIR,
    "ForenXAI_Cases"
)

os.makedirs(
    CASE_OUTPUT_DIR,
    exist_ok=True
)


# ============================================================
# CICFLOWMETER V4 CONFIGURATION
# ============================================================

# CICFlowMeter v4 installation
CICFLOWMETER_DIR = r"C:\Tools\CICFlowMeter\installed\CICFlowMeter-4.0"

# Working Windows launcher
CICFLOWMETER_EXECUTABLE = os.path.join(
    CICFLOWMETER_DIR,
    "bin",
    "cfm.bat"
)

# Java executable
CICFLOWMETER_JAVA = "java"

# jNetPcap native libraries
CICFLOWMETER_NATIVE_DIR = os.path.join(
    CICFLOWMETER_DIR,
    "lib",
    "native"
)

# JAR location
CICFLOWMETER_JAR = os.path.join(
    CICFLOWMETER_DIR,
    "lib",
    "CICFlowMeter-4.0.jar"
)


# ============================================================
# FLOW EXTRACTION ENGINE
# ============================================================

# Which engine turns a PCAP into flow records.
#
#   "auto"    use CICFlowMeter v4 when it is installed and working,
#             otherwise fall back to the pure-Python extractor
#   "java"    require CICFlowMeter v4; fail if it is unavailable
#   "python"  always use the pure-Python extractor
#
# Both use a 120 s flow timeout, but they differ on activity, bulk and
# subflow boundaries, so feature values are close rather than identical.
# Whichever ran is recorded next to the flow CSV in flow_extraction.json,
# and carried on the DataFrame as df.attrs["flow_engine"], so a finding can
# always be traced to the engine that produced it.
#
# The Python engine is also bounded by memory: it holds a flow's packets
# until the flow closes. A dense capture is refused with instructions for
# splitting it. CICFlowMeter v4 has no such limit.
#
# Override for one run without editing this file:
#     set FORENXAI_FLOW_ENGINE=java

FLOW_ENGINE = os.environ.get(
    "FORENXAI_FLOW_ENGINE",
    "auto"
).strip().lower()

if FLOW_ENGINE not in ("auto", "java", "python"):
    raise ValueError(
        f"FORENXAI_FLOW_ENGINE is {FLOW_ENGINE!r}. "
        "It must be one of: auto, java, python."
    )