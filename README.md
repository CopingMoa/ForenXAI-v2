# ForenXAI: Explainable PCAP Network Anomaly Detection Forensic Tool

ForenXAI is an advanced network forensic tool featuring an intrusion detection pipeline that combines high-performance ensemble machine learning with post-hoc Explainable AI (XAI) to analyze PCAP files uploaded by the user. The machine learning models are trained using UWF-ZeekData24 telemetry logs against the MITRE ATT&CK framework, augmented with a human-in-the-loop mechanism.


## Pipeline Architecture

* **Core Modeling:** High-throughput ensemble classification (decision tree, random forest, lightgbm xgboost , extra tree, regression for meta learning) optimized for imbalanced enterprise network traffic.
* **Explainability Engine:** SHAP (SHapley Additive exPlanations) integration to provide transparent, instance-level attribution for zero-day anomalies and malicious tactics.
* **Data Foundation:** Processes structured flow metrics from enterprise Zeek logs mapped directly to MITRE ATT&CK tactics (e.g., Credential Access, Reconnaissance).


## To Add Later (if there is time):

* **EBM (Explainable Boosting Machines):** "glass-box" models that decompose predictions into additive contributions from individual features (and optional pairwise interactions), allowing for clear visualization of how each variable affects the outcome. They offer accuracy comparable to black-box models like XGBoost or Random Forest while remaining fully transparent.

## Download / Fetch the dataset from Google Drive:
https://drive.google.com/drive/folders/1Q8MvO3O-SyuC1N0NaBsA61fhi6xC2bzz?usp=sharing 
