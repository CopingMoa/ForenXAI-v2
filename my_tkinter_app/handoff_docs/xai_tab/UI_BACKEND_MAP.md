# UI ↔ backend, field by field

Every widget in the two tabs, the backend field behind it, and what the
renderer owes that field. If you are rewriting the interface, this is the
contract — not `xai_tab.py`, which is one implementation of it.

Smoke section **F — INTEGRATION** runs every renderer against real service
output, so a rename on either side fails there rather than surfacing as a
blank panel at run time. Add your renderer to it.

---

## Tab 1 — forensic analysis

| Widget | Backend field | Notes |
|---|---|---|
| Case ID | `current_case["case_id"]` | |
| Evidence hash | `current_case["pcap_sha256"]` | show it — it is why the analysis is repeatable |
| Flow / benign / threat counts | `total_flows`, `benign_flows`, `threat_flows` | arrive via `on_metrics_ready` **before** SHAP finishes |
| Class breakdown table | `class_breakdown`, `model_classes` | |
| Log pane | `log_fn(str)` callback | called throughout; this is the progress signal |
| Artefact list | the six `*_path` / `*_sha256` pairs | pair each path with its hash in the same row |
| Extractor notice | `flow_extraction.json` beside the CSV | says which engine ran — a fact about the evidence, not a diagnostic |

**The seam:** `xai_tab.update_xai_results(current_case, shap_results)`.
`shap_results` is accepted and ignored — Tab 2 recomputes attributions with
the sixteen-class bundle. Tab 2 reads three fields off the case:
`generated_csv_path`, `pcap_path`, `pcap_sha256`.

---

## Tab 2 — panel 1, flow summary

Built by `summarise_capture()`. Everything is on `result["summary"]`.

| Widget | Backend field | Notes |
|---|---|---|
| Stat strip | `facts` | `total_flows`, `benign_flows`, `attack_flows`, `attack_share`, `distinct_attack_classes`, `mean_confidence`, `low_confidence_flows` |
| Provenance lines | `lines` | already ordered PCAP → CSV → analysis; render in order |
| Capture window | `facts["capture_window"]` | `span_human` is pre-formatted; do not recompute from the timestamps |
| Endpoints | `facts["endpoints"]` | busiest sources and targets |
| Intake notice | `intake` | a truncated file or a high coercion rate changes what every other number means |
| Capture link | `capture_link` | whether this flow table describes *this* capture |
| Extraction record | `extraction`, `facts["flow_engine"]` | which extractor produced the table |
| Paragraph | `narrative` | absent or fallback → still render the figures above |

## Tab 2 — panel 2, why this class

Built by `explain_detections()`. On `result["shap"]`, under `detections[0]`.

| Widget | Backend field | Notes |
|---|---|---|
| Findings list | `result["findings"]` | one row per class; selecting one re-runs panels 2 and 3 |
| Predicted class + confidence | `model_output` | |
| Runner-up | `runner_up`, `runner_up_confidence` | |
| Diverging bars | `attributions[].contribution` | **log-odds.** Never label as a percentage |
| Bar label | `attributions[].plain` | plain English, not the raw feature name |
| Value beside the bar | `attributions[].readable` | already converted with its unit |
| Comparison | `attributions[].magnitude` | `"typical for this feature"` or `"N standard deviations above the training mean"` |
| Direction | `attributions[].direction` | `supports` / `argues against` — colour the bar by this, not by the sign alone |
| Warning icon | `attributions[].caution` | present on features the model may be leaning on for the wrong reason |
| Additivity check | `shap_check` | `agrees`, `additivity_error`, `shown_share_of_total`, `reconstruction_picks_predicted` |
| Paragraph | `narrative` | class name is deliberately absent from it |

## Tab 2 — panel 3, what to do

Built by `recommend()`. Everything is on `result["recommend"]`.

| Widget | Backend field | Notes |
|---|---|---|
| Heading | `class` | |
| Retrieved blocks | `sections` | `heading` + `body`; **render in order — order is triage order** |
| Block styling | `sections[].kind` | `playbook` / `explainer` / `glossary` |
| Source label | `sections[].source` | which file the block came from |
| Verification badge | `sections[].verified_against` | `"source"` = checked against the PDF; `"cache"` = against extracted text. **Two different claims — do not collapse them** |
| Quote count | `sections[].quotes_verified` | how many passages were checked |
| Reference list | `references` | full ACM-format citations |
| `[n]` markers | `reference_map` | derived after the checks; never write your own |
| Ambiguity notice | `ambiguity` | **show when present** — the model saying it cannot separate two classes |
| Unavailable guidance | `missing_documents` | name what is missing; substitute nothing |
| Quarantine banner + Repair | `unverified_documents` | **never render their content**; repair is a decision someone takes and sees the result of |
| Evidence beside the steps | `evidence` | the top three attributions from panel 2, taken from there rather than recomputed |
| Which rules fired | `model_guidance` | optional, useful in a detail view |

---

## Cross-cutting

| Concern | Contract |
|---|---|
| Threading | `build_panels()` blocks for 44 s warm, 58 s cold. Run it on a worker; marshal every widget update back to the main thread |
| Progress | `on_progress=callable(str)` — one sentence per stage, carrying the finding's own figures. A callback that raises cannot fail the analysis |
| New capture | Clear all three panels, the findings list, the quarantine banner **and the investigator's review**, before any early return. Carry a run id so a slow worker cannot repaint a superseded result |
| Errors | `result["error"]` is written for a dialog box. Display it verbatim |
| No model | `narrate_with=None` or an unreachable model → every figure, label and citation still renders. Narration is additive |
| Diagnostics | `narration_findings`, removed phrases, withheld features are **console output**. The panel shows the capture; the console shows the machinery |
