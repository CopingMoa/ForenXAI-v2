# ForenXAI: Explainable PCAP Network Anomaly Detection Forensic Tool

## Project Overview

ForenXAI is a digital forensics and network anomaly detection tool for analyzing user-supplied PCAP / PCAPNG evidence. It combines machine learning, calibrated prediction, and post-hoc explainability (SHAP) to support forensic review of suspicious network flows.

**Tech Stack:**
*   Language: Python
*   GUI: Tkinter
*   Build Tool: PyInstaller (for standalone executable generation)
*   OS Target: Windows 10 / 11 64-bit (desktop forensic use)

---

## Architectural Constraints (CRITICAL)

The system is built around a **strict separation** between three environments. Do not blend these pipelines in code or proposals:

1.  **Offline Model Development:** Used only for model creation, calibration, and evaluation.
2.  **Frozen Deployment Artifacts:** The trained model, preprocessing pipeline, feature schema, label encoder, calibrator, and SHAP background data must be frozen.
3.  **Online Forensic Inference:** The user-facing tool. Must not alter the frozen artifacts.

---

## Research & Data Methodology

The evaluation design strictly enforces the following dataset roles across two major experimental phases:

*   **[Experiment 1] Merged Dataset (Baseline):** The initial methodology leveraging a merged multi-source dataset (TII-SSRC-23 and CSE-CIC-IDS2018) to establish baselines, which ultimately revealed dataset-origin leakage.
*   **[Experiment 2] Parallel Pipeline (Refined):** The corrected methodology where TII-SSRC-23 & CSE-CIC-IDS2018 undergo identical, **parallel processing pipelines** to eliminate leakage and enforce strict external validation.
*   **CIC-IoT-IDAD-Dataset-2024:** Used strictly for **external binary validation** (real network traffic/malware traces) of the frozen models.

---

## 1. Experiment 1: Merged Dataset Architecture (The Baseline)

Experiment 1 covers the initial workflow using a merged multi-source dataset. This experiment was conducted across two distinct iterations (Version 1 and Version 2) to refine feature selection and model diversity before the discovery of origin leakage.

### 1.1 Phases 1–4: Data Acquisition, Audit, and Cleaning
*   **Data Sources:** Integrates **CSE-CIC-IDS2018** (background traffic and tool-based attacks) and **TII-SSRC-23** (modern attacks like Mirai botnets).
*   **Data Repair:** Removed 59 corrupted header rows containing literal text labels and purged `Infinity`/`NaN` values caused by division-by-zero durations.

### 1.2 Phase 5: Label Preparation and Schema Alignment
*   **Schema Alignment:** CICIDS2018 used CICFlowMeter V3, while TII-SSRC-23 used V4. A 48-column rename map was applied to align schemas.
*   **Label Mapping:** Raw labels were unified into standard classes (Benign, DoS, Botnet, Bruteforce, Infiltration, Info-Gathering), producing a merged dataset of **1,160,639 rows**.

### 1.3 Phases 6–7: Data Split and Feature Selection
*   **Method:** Boruta evaluated features against randomized "shadow features" on a stratified 100,000-row training subsample using a Random Forest estimator.
*   **Highlighted Iterations:**
    *   **[Version 1]:** Reduced the feature space from 78 to **68 features**, rejecting constant-zero columns.
    *   **[Version 2]:** Further refined feature convergence down to a confirmed **64 features**.

### 1.4 Phases 8–10: Optimization, Imbalance Handling, and Base Training
*   **Optimization:** Executed 25 Optuna trials per model using Tree-structured Parzen Estimator (TPE) optimized for `macro F1` across a 3-fold stratified cross-validation.
*   **Highlighted Iterations:**
    *   **[Version 1]:** Evaluated exclusively **tree-based algorithms** (LightGBM, XGBoost, Random Forest).
    *   **[Version 2]:** Expanded to **non-tree algorithms** (MLP, Logistic Regression, Linear SVM) and compared artificially balanced training sets against realistic, imbalanced training proportions.

### 1.5 Phases 11–13: Ensemble Stacking and Calibration
*   **Meta-Learner:** Combined base learners using a Logistic Regression meta-learner via out-of-fold cross-validated probability predictions.
*   **Calibration:** Evaluated via multiclass Brier score yielding **0.0938**, indicating reliable probability calibration.

### 1.6 Phases 14–16: Evaluation and Leakage Discovery
*   **Critical Finding:** An origin-prediction classifier achieved exactly **1.0000 (100%) accuracy** in predicting which dataset a flow came from.
*   **Root Cause:** Features like initial TCP window sizes and inter-arrival times acted as environment fingerprints rather than pure attack behaviors, artificially inflating aggregate accuracy metrics.

---

## 2. Experiment 2: Parallel Pipeline Architecture 

### 2.1 Phases 1–4: Data Acquisition, Audit, and Environment Isolation
*   **Environment Isolation:** The pipeline strictly audits for missing values and explicitly **removes capture-environment identifiers** (e.g., Flow ID, IPs, Ports, Timestamps) to prevent the model from artificially memorizing collection artifacts. 
*   **Data Validation:** Valid flows are loaded while zero-duration infinites are handled.

### 2.2 Phase 5: Label Preparation and Experimental Setup
*   **Encoding:** Targets are integer-encoded to standardize modeling. 
*   **Model 2 Focus:** Explicitly narrows its focus to multiclass classification of purely malicious traffic sub-types (DoS, Bruteforce, Information Gathering, and Botnet), requiring granular N×N confusion matrices to prevent major attack classes from masking minor ones.

### 2.3 Phases 6–7: Data Split and Feature Selection
*   **Data Split:** Implements a robust 70/15/15 stratified split.
*   **Hierarchical Selection:** Because the dataset comprises millions of records, Hierarchical Feature Selection (Single-Pass LightGBM Gain) is implemented over BorutaSHAP to efficiently handle multicollinearity and scale computationally.

### 2.4 Phases 8–10: Optimization, Imbalance Handling, and Base Training
*   **Optimization:** Internal cross-validation via Optuna optimizes toward macro-F1. Seven distinct base classifiers are trained.
*   **Imbalance Handling:** To address extreme class imbalances natively without synthesizing millions of points, cost-sensitive weighting (`class_weight='balanced'`) replaces SMOTE.
* **Base Training:**
* Logistic Regression	Glass-box	Fully transparent baseline; coefficients are directly interpretable
* CART Decision Tree	Glass-box	Transparent, rule-based; captures nonlinear splits
* Extra Trees	Black-box	High variance reduction via extra randomization
* Random Forest	Black-box	Robust bagging baseline
* LightGBM	Black-box	Fast gradient boosting, handles large feature sets efficiently
* CatBoost	Black-box	Strong on categorical-heavy flow features, resistant to overfitting
* XGBoost	Black-box	Regularized boosting; consistently top-performing in IDS literature

### 2.5 Phases 11–13: Ensemble Stacking and Calibration
*   **Meta-Learner:** Out-of-fold base model predictions are stacked as features for a final Logistic Regression Meta-Learner. 
*   **Calibration:** Tree-based predictions undergo Isotonic regression calibration, while linear boundaries use Platt scaling, ensuring generated confidence scores map accurately to real probabilities.

### 2.6 Phases 14–16: XAI, External Validation, and Artifact Saving
*   **Explainability:** Post-calibration, a SHAP `TreeExplainer` maps feature contributions per class.
*   **External Validation:** The entire pipeline (hyperparameters, calibrators, weights) is strictly frozen and pushed against an untouched external dataset (**CIC-IoT-IDAD-Dataset-2024**) formatted via a version-locked CICFlowMeter.
*   **Artifact Saving:** All models and selectors are persisted using loadable `joblib`/`pickle` objects for absolute forensic auditability.

---

## License

**MIT License**

Copyright (c) 2026 ForenXAI Project

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
