
# ForenXAI: Explainable PCAP Network Anomaly Detection Forensic Tool

ForenXAI is a digital forensics and network anomaly detection tool for analyzing user-supplied PCAP / PCAPNG evidence. It combines machine learning, calibrated prediction, and post-hoc explainability to support forensic review of suspicious network flows.

The current design uses a **single primary training dataset** and **two external validation datasets**:

- **TII-SSRC-23** — primary training dataset
- **CIC-IDS2018** — external multiclass validation
- **CTU-13** — external binary validation on real network traffic and malware traces

The system is built around a strict separation between:

1. **Offline model development**
2. **Frozen deployment artifacts**
3. **Online forensic inference**

---

## Core Goals

- Detect malicious or anomalous network flows from PCAP evidence
- Produce calibrated prediction scores rather than raw class outputs
- Provide instance-level explanations using SHAP
- Preserve evidence integrity through hashing and audit logging
- Support analyst review with Confirm / Reject / Inconclusive decisions

---

## System Architecture

### 1. Offline Development Pipeline

The development pipeline is used only for model creation and evaluation.

- **Training data:** TII-SSRC-23
- **Model selection:** Logistic Regression, CART Decision Trees, Extra Trees, LightGBM, XGBoost
- **Validation strategy:** group-aware splitting with leakage-safe preprocessing
- **Imbalance handling:** class weights or SMOTE applied only to training folds
- **Calibration:** Platt scaling or isotonic regression on untouched hold-out data
- **External validation:** CIC-IDS2018 and CTU-13
- **Artifact freezing:** trained model, preprocessing pipeline, feature schema, label encoder, calibrator, SHAP background data

### 2. Operational Forensic Pipeline

The operational pipeline is the user-facing tool.

- PCAP / PCAPNG ingestion
- SHA-256 evidence hashing
- CICFlowMeter-based flow extraction
- Extraction validation
- Schema validation
- Frozen preprocessing
- Frozen model inference
- Calibrated confidence scoring
- SHAP explanation on attack, low-confidence, or analyst-requested cases
- Analyst decision capture
- Forensic report generation
- Immutable audit logging

---

## Development Data Flow

### TII-SSRC-23
TII-SSRC-23 is the only dataset used for training and model selection.

Processing steps:

1. Load Parquet partitions
2. Merge partitions into a master table
3. Audit for:
   - duplicates
   - missing values
   - invalid values
   - label consistency
4. Clean and validate features
5. Split using a group-aware strategy
6. Fit preprocessing only on training folds
7. Train and tune candidate models
8. Select the champion model
9. Calibrate probabilities on non-SMOTEd hold-out data

### External Validation

#### CIC-IDS2018
Used only for frozen-model multiclass evaluation.

#### CTU-13
Used only for frozen-model binary evaluation.  
PCAP files are converted using a version-locked CICFlowMeter pipeline to maintain feature compatibility.

---

## Model Pipeline

### Candidate Models
- Logistic Regression (Glass-box model)
- CART Decision Tree (Glass-box model)
- Extra Trees (Black-box model)
- LightGBM (Black-box model)
- CatBoost (Black-box model)
- XGBoost(Black-box model)

### Optional Future Model
- EBM (Explainable Boosting Machines)

EBM is a future enhancement candidate for a more interpretable glass-box baseline. It is not required for the current implementation.

### Model Selection
Model candidates are compared using:
- cross-validated performance
- Friedman test
- Nemenyi post-hoc comparison

### Calibration
The selected model is calibrated to produce usable confidence estimates for forensic analysis.

---

## Explainability

ForenXAI uses SHAP to explain predictions.

Explainability is triggered when:
- the prediction is malicious,
- the confidence score is below threshold,
- or the analyst requests an explanation manually.

This keeps the application responsive while still exposing meaningful explanations for suspicious cases.

---

## User Workflow

1. User uploads PCAP / PCAPNG evidence
2. System computes SHA-256 hash
3. Flow extraction runs through CICFlowMeter
4. Output is validated against the frozen schema
5. Frozen model generates a calibrated prediction
6. SHAP explanation is generated when needed
7. Analyst reviews the result
8. Analyst chooses:
   - Confirm
   - Reject
   - Inconclusive
9. System generates a forensic report and audit log

---

## Output Artifacts

The tool generates:

- prediction results
- calibrated confidence scores
- SHAP explanation summaries
- forensic reports
- hash records
- audit logs

---

## Current Scope

### Included
- TII-SSRC-23-based training
- CIC-IDS2018 external validation
- CTU-13 external validation
- PCAP / PCAPNG analysis
- XAI explanations
- analyst decision support
- evidence integrity tracking

### Not in current scope
- live packet interception
- retraining from user evidence
- direct MITRE ATT&CK mapping as the primary modeling target
- multi-dataset training across TII-SSRC-23, CIC-IDS2018, and CTU-13

---

## Dataset Access

### Primary Dataset
- TII-SSRC-23

### External Validation Datasets
- CIC-IDS2018
- CTU-13

Dataset sources and fetch instructions will be documented separately.

---

## Compatibility

### Operating System
- Windows 10 / 11 64-bit

### Notes
- The tool is designed for desktop forensic use.
- Large PCAPs may require background extraction and validation.
- The CICFlowMeter version used in deployment should remain consistent with the development pipeline.

---

## Project Summary

ForenXAI is a forensic ML system that separates **training**, **validation**, and **deployment** cleanly.  
Its goal is not only to classify network traffic, but also to make the result explainable, auditable, and suitable for forensic review.
