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

# Recommended:
#
# Set CICFLOWMETER_JAR to the location of your
# CICFlowMeter-4.0.jar.
#
# Example Windows:
#
# set CICFLOWMETER_JAR=C:\Tools\CICFlowMeter\CICFlowMeter-4.0.jar
#
# Or use an environment variable permanently.
#
CICFLOWMETER_JAR = os.environ.get(
    "CICFLOWMETER_JAR",
    ""
)


# Java executable.
#
# Usually "java" is sufficient if Java is already in PATH.
#
CICFLOWMETER_JAVA = os.environ.get(
    "CICFLOWMETER_JAVA",
    "java"
)


# Optional native jNetPcap directory.
#
# CICFlowMeter v4 uses jNetPcap. If the JAR requires the native
# DLL directory to be explicitly supplied, configure this.
#
# Example:
#
# C:\Tools\CICFlowMeter\jnetpcap\win\jnetpcap-1.4.r1425
#
CICFLOWMETER_NATIVE_DIR = os.environ.get(
    "CICFLOWMETER_NATIVE_DIR",
    ""
)


# Optional direct executable.
#
# This can be used if you have a CICFlowMeter command wrapper
# such as CICFlowMeter.bat / cfm.bat.
#
# If this is configured, it takes priority over the JAR.
#
CICFLOWMETER_EXECUTABLE = os.environ.get(
    "CICFLOWMETER_EXECUTABLE",
    ""
)