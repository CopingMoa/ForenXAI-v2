# Tab 1 — Forensic analysis

Takes a PCAP the investigator uploaded and turns it into a case: flows,
predictions, SHAP, a report on disk, and a SHA-256 for every file it wrote.

This tab **produces** the evidence. Tab 2 explains it. They meet at one
place only: `current_case["generated_csv_path"]`.

---

## Quickstart

```bash
py -3.11 -m pip install -r ../requirements.txt
cd .. && python smoke_test.py          # expect 122/122
```

That is the whole setup for this tab. **No language model, no corpus** —
`ollama` and `xai_tab/knowledge/` are Tab 2's, and nothing here touches
them.

Everything this tab loads is in this folder already:

| File | What it is |
|---|---|
| `artifacts/…/model.joblib` | the classifier, wrapped in a Pipeline that scales its own input |
| `artifacts/…/frozen_feature_schema_l2.json` | the column order it was fitted on |
| `forensic_tab.py` | the working renderer — reference, not a requirement |

Then write your renderer against **one call** — `run_forensic_pipeline()`,
below. Run it off the UI thread; it blocks for tens of seconds.

**Optional:** CICFlowMeter v4 + JDK 8 make PCAP extraction match the
reference implementation exactly. Without them a pure-Python extractor
takes over automatically, with the two limits noted under "Two extractors".

---

**The notes in this folder:** this file. The widget-by-field contract for
this tab lives with the other one, in
[../xai_tab/UI_BACKEND_MAP.md](../xai_tab/UI_BACKEND_MAP.md), because it
covers both. Everything this tab loads is in this folder — see
[../START_HERE.md](../START_HERE.md) for the layout.

**This tab uses no language model** and never opens `xai_tab/knowledge/`.

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

> Every widget in this tab against the field behind it:
> **[../xai_tab/UI_BACKEND_MAP.md](../xai_tab/UI_BACKEND_MAP.md)**.


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

## What is in this folder

Everything this tab loads, and nothing it does not.

```
forensic_tab/
├── forensic_tab.py
├── README.md                       (this file)
└── artifacts/ForenXAI-Multiclass/forensic_tab/
    ├── model.joblib                27 MB  the sklearn Pipeline
    └── frozen_feature_schema_l2.json      the column order it was fitted on
```

`model_service.ARTIFACTS_DIR` resolves to `forensic_tab/artifacts` here and
to `artifacts/` in the development tree, so the same code reads both.
`discover_models()` scans it — drop another dataset's folder in beside
`ForenXAI-Multiclass` and it appears in the selector.

**Nothing here is a duplicate of Tab 2's copy.** `model.joblib` is the
sklearn Pipeline the forensic chain runs; `xai_tab/models/forenxai/
XGBoost.pkl` is the same estimator serialised without the pipeline, with the
scaler, encoder and feature list the panels need. Each tab loads one and
never the other.

Shared at the root, because both tabs use them: `services/` (350 KB of code
— two copies of a module is how they drift) and `sample_data/` (a flow table
to develop against without a PCAP).

Not needed here at all: `xai_tab/knowledge/`, and no language model is
involved in this tab.

## Check it works

```bash
python smoke_test.py          # 77 checks; section C covers refusals
```

Section **C — INPUT** is the one for this tab: it feeds a capture that
cannot be analysed and asserts the refusal is a message, not a traceback.
