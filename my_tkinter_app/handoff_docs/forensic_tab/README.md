# Tab 1 — Forensic analysis

Takes a PCAP the investigator uploaded and turns it into a case: flows,
predictions, SHAP, a report on disk, and a SHA-256 for every file it wrote.

This tab **produces** the evidence. Tab 2 explains it. They meet at one
place only: `current_case["generated_csv_path"]`.

---

## The one call

```python
from services.pipeline_service import run_forensic_pipeline

current_case, shap_results = run_forensic_pipeline(
    pcap_path,          # .pcap or .pcapng the investigator chose
    model,              # loaded estimator, from model_service.load_model()
    model_name,         # "ForenXAI-Multiclass"
    case_output_dir,    # where the case folder is created
    log_fn,             # callable(str) -- your log widget
    on_metrics_ready,   # optional callable(total, benign, threat)
)
```

Everything else in this tab is presentation. `run_forensic_pipeline` is
blocking and takes tens of seconds on a real capture, so **run it off the UI
thread** — `forensic_tab.py:2511` shows the worker thread, and `root.after`
marshals every widget update back to the main thread. Tk is not thread-safe;
calling a widget from the worker raises, intermittently.

`log_fn` is called throughout, so the investigator sees the stage names as
they happen rather than a frozen window. `on_metrics_ready` fires as soon as
the counts are known, before SHAP, which is the slow part.

## The chain inside it

```
PCAP  ->  SHA-256  ->  CICFlowMeter v4  ->  flow CSV  ->  DataFrame
      ->  feature normalisation  ->  frozen schema  ->  prediction
      ->  SHAP  ->  forensic report
```

Each arrow is a place it can refuse. A refusal carries a message written for
a dialog box — show it verbatim rather than rewording it.

| File | What it does here |
|---|---|
| `services/pipeline_service.py` | `run_forensic_pipeline` — the whole chain above. Also `save_investigator_review`, which Tab 2 calls. |
| `services/model_service.py` | `discover_models`, `load_model`, `load_feature_schema`, `get_family_mapping`, `get_class_names`. Model discovery scans `artifacts/`. |
| `services/cicflowmeter_service.py` | Runs CICFlowMeter v4 when it is installed. |
| `services/pyflow_extractor.py` | The pure-Python fallback when it is not. See "Two extractors" below. |
| `services/shap_service.py` | TreeSHAP over the predicted flows, and the importance plot. |
| `services/utils.py` | Hashing and small path helpers. |

## What lands on disk

`current_case` comes back with **19 keys**. The pattern that matters: every
artefact has a path *and* a hash beside it.

| Path key | Hash key |
|---|---|
| `cicflowmeter_csv_path` | `cicflowmeter_csv_sha256` |
| `generated_csv_path` | `generated_csv_sha256` |
| `prediction_path` | `prediction_sha256` |
| `report_path` | `report_sha256` |
| `shap_path` | `shap_sha256` |
| `pcap_path` | `pcap_sha256` |

Plus the counts the header shows — `total_flows`, `benign_flows`,
`threat_flows`, `class_breakdown`, `model_classes` — and the three review
fields `save_investigator_review` writes back: `investigator_decision`,
`investigator_comment`, `review_timestamp`.

**Show the hashes.** They are the reason a defence expert can repeat the
analysis, and they cost one label each in the UI.

## Two extractors, and why the UI must say which ran

CICFlowMeter v4 is the reference implementation the model was trained
against. It needs `jnetpcap` native libraries that frequently will not
install on Windows, so `pyflow_extractor.py` takes over automatically.

The fallback is not identical:

- it holds a flow's packets until that flow closes, so a dense capture is
  **refused with instructions** rather than exhausting memory — around
  600,000 packets is the ceiling;
- activity, bulk and subflow columns sit on slightly different boundaries.

Which engine ran is recorded in `flow_extraction.json` beside the CSV, and
the Flow Summary panel in Tab 2 prints it. A timing feature only means
something against the extractor that computed it, so this is a fact about
the evidence, not a diagnostic.

## Handing over to Tab 2

`MainWindow` passes the case straight across:

```python
self.xai_tab.update_xai_results(current_case, shap_results)
```

`shap_results` is accepted and **ignored** — Tab 2 recomputes attributions
from the flow CSV with the sixteen-class bundle, which the legacy per-flow
list does not have. It stays in the signature so `MainWindow` needs no edit.

What Tab 2 actually reads off the case: `generated_csv_path`, `pcap_path`
and `pcap_sha256`. It re-verifies that the flow table describes *this*
capture rather than trusting the path — `verify_capture_link()` — using the
hash you already computed, not a fresh one.

## Data this tab needs

| | |
|---|---|
| `artifacts/ForenXAI-Multiclass/` | The model this build ships. `discover_models()` scans this folder; drop another dataset's folder in and it appears in the selector. |
| `models/forenxai/` | The same XGBoost as a plain `.pkl` with its scaler, encoder and feature list. See the root README for which to load. |
| `sample_data/` | A flow table to develop against without a PCAP. |

Not needed here: `knowledge/` is Tab 2's corpus, and no language model is
involved in this tab at all.

## Check it works

```bash
python smoke_test.py          # 77 checks; section C covers refusals
```

Section **C — INPUT** is the one for this tab: it feeds a capture that
cannot be analysed and asserts the refusal is a message, not a traceback.
