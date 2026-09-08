# ForenXAI — model, SHAP and RAG handoff

Everything needed to run the classifier, the SHAP explanations and the
recommendations panel. No Tkinter required: every function here returns a
dict, so you can render it in whatever UI you are building.

Built by `make_handoff.py`. The test suite was run inside this folder before
it was sent: **122/122 passing**.

---

## 1. Install

```bash
pip install -r requirements.txt
python test_panels_suite.py       # must print 122/122 checks passed
```

If the suite passes, integration is a matter of calling one function.

CICFlowMeter v4 is **optional**. It is not installed here and the code falls
back to a pure-Python extractor automatically. See §6.

---

## 2. The one call you need

```python
from services.panels_service import build_panels

result = build_panels(
    csv_path="path/to/flows.csv",   # CICFlowMeter-format CSV
    source_name="evidence.pcap",    # shown to the investigator
    finding_index=0,                # which finding to explain
)
```

Returns a dict. Never raises for bad input — check `result` for `"error"`
first and display it verbatim; the messages are written for a dialog box.

```python
if "error" in result:
    show_dialog(result["error"])
    return
```

### What comes back

| Key | Type | Panel |
|---|---|---|
| `summary` | dict | 1 — Flow Summary |
| `findings` | list | the selectable list of findings |
| `selected` | dict | the finding `finding_index` picked |
| `shap` | dict | 2 — SHAP attributions |
| `recommend` | dict | 3 — Recommendations |

`findings` is what the user picks from. Re-call `build_panels` with a new
`finding_index` when they select a different row — it is cheap
(~20 microseconds per flow to classify, 8.1 ms for the two explained rows).

---

## 3. Panel by panel

### Panel 1 — `result["summary"]`

```python
summary["facts"]    # dict of numbers: total_flows, attack_flows,
                    # mean_confidence, capture_window, endpoints, ...
summary["lines"]    # list[str], ready to print one per line
```

Render `lines` as text and `facts` as a stat grid. Two keys need special
handling:

- `facts["flow_timeout_warning"]` — `True` means every timing feature is
  suspect. **Show this prominently.**
- `facts["flow_engine"]` — `"java"` or `"python"`. Which extractor produced
  the flows. Belongs on screen; see §6.

### Panel 2 — `result["shap"]`

```python
shap["detections"]      # list, one per explained flow
shap["units"]           # str — PRINT THIS. Values are log-odds, not %
```

Each detection has `top_features`, each with `feature`, `shap_value`,
`raw_value` and a plain-English `label`.

**Do not render a SHAP value as a percentage.** They are log-odds. The
`units` string says so; keep it visible above the list.

### Panel 3 — `result["recommend"]`

```python
rec["sections"]     # list of {heading, body, citations, kind}
rec["references"]   # list[str] — full IEEE citations
rec["citations"]    # which files were quoted
rec["missing_documents"]
```

Render `sections` in order. Each has `kind`:

- `kind` absent → guidance about the **attack**
- `kind == "model"` → guidance about **how far to trust the result**

Put a divider before the first `"model"` section. `reference/xai_tab.py`
does this at `_render_recommend()` — copy the approach, not the widgets.

**Every section carries `citations`.** Show them. A recommendation without
its source is an assertion.

---

## 4. Which folder holds what

```
models/forenxai/            * the 16-class XGBoost + scaler + encoder,
                              loaded by panels_service. Do not edit.
artifacts/ForenXAI-Multiclass/
                            * the SAME model wrapped as a sklearn Pipeline
                              for the forensic pipeline. See §5.
services/                   * all logic. panels_service.py is the entry.
knowledge/                  * the RAG corpus. See knowledge/README.md for
                              the folder rules and retrieval map.
reference/xai_tab.py        * a working Tkinter renderer. Reference only.
sample_data/                * fixture the test suite runs against.
```

---

## 5. The two model copies are the same model

`models/forenxai/XGBoost.pkl` and the estimator inside
`artifacts/ForenXAI-Multiclass/forensic_tab/model.joblib` are byte-identical
(SHA-256 prefix `5c123326d779f600`). The second is wrapped in a Pipeline so
`.predict()` scales the input itself.

**Both leading Pipeline steps matter.** The model was trained on **float32**;
passing float64 gives numerically identical features but a different class
on 12.7% of a real capture, because split thresholds were learned in
float32. If you build your own inference path, cast to float32 and apply the
scaler — or just use the Pipeline.

`python deploy_multiclass_model.py` rebuilds and re-verifies it.

---

## 6. PCAP input

```python
from services.cicflowmeter_service import extract_flows_from_pcap
df, csv_path = extract_flows_from_pcap(pcap_path, case_dir, log_fn)
```

`log_fn(message, kind)` is called with progress; `kind` is one of
`"info"`, `"success"`, `"warning"`, `"error"`.

CICFlowMeter v4 is used when installed, otherwise a pure-Python fallback
runs automatically. Which one ran is written to
`case_dir/flow_extraction.json` and set on `df.attrs["flow_engine"]`.

Two limits of the fallback, both surfaced to the user rather than hidden:

- It holds a flow's packets until the flow closes, so a dense capture is
  refused with instructions to split it (roughly 600,000 packets is the
  ceiling). The error text names the `editcap` command.
- Activity, bulk and subflow columns sit on slightly different boundaries
  than CICFlowMeter v4 uses.

To force one engine: set `FORENXAI_FLOW_ENGINE` to `java`, `python` or
`auto` before import.

---

## 7. Local LLM narration — optional, off by default

The panels are complete without it. Narration only adds prose beside
figures that are already correct, so a missing or broken model degrades the
panel rather than emptying it.

```python
result = build_panels(csv_path, source_name, narrate_with="ollama")
```

See `OLLAMA.md`. Leave `narrate_with=None` if you are not wiring it up.

Narration is checked before display: `services/narration_schema.py` flags a
log-odds value written as a percentage, a citation that was never supplied,
and figures absent from the input. Findings appear in
`result["summary"]["narration"]["findings"]` — show them if non-empty.

---

## 8. Things that will bite you

**Do not re-order the feature columns.** `models/forenxai/features.pkl` is
the exact order the model expects. `flow_intake.to_matrix()` handles it.

**Do not call the model directly on a raw CSV.** `read_flows()` validates
the file and refuses hostile input with a message fit for a dialog. Skipping
it means confident predictions from a table whose columns mean something
else.

**Do not present a class name as a conclusion.** DoS scores F1 0.6703 and
Slowloris 0.7593 on held-out data. The recommendations panel says so when it
applies; do not truncate that section away.

**No MITRE ATT&CK.** It was removed deliberately — ATT&CK describes
host-observed behaviour and this tool sees flow records. Do not add a
technique column.

---

## 9. Contact points in the code

| You want | Look at |
|---|---|
| Add a class document | `knowledge/README.md`, then `KNOWLEDGE_MAP` |
| Change when model guidance appears | `MODEL_GUIDANCE` in `panels_service.py` |
| Check a citation is real | `python fetch_knowledge.py --verify` |
| Rebuild the deployed model | `python deploy_multiclass_model.py --write` |
| See the expected rendering | `reference/xai_tab.py` |
