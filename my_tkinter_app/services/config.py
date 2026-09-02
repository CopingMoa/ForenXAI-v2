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