import os

# ============================================================
# CONFIGURATION
# ============================================================
# BASE_DIR is the project root (one level above services/),
# so paths stay correct no matter whose machine runs main.py.

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

MODEL_PATH = os.path.join(BASE_DIR, "models", "rf.pkl")
CASE_OUTPUT_DIR = os.path.join(BASE_DIR, "ForenXAI_Cases")

os.makedirs(CASE_OUTPUT_DIR, exist_ok=True)
