# Tab 2 — Explanation

Takes the flow table Tab 1 produced and answers three questions, one per
panel: what is in this capture, why did the model say that, and what should
be done about it.

One call fills all three.

---

## Where the tab is entered

`MainWindow` calls one method when Tab 1 finishes:

```python
xai_tab.update_xai_results(current_case, shap_results)
```

`shap_results` is the legacy per-flow list — accepted and ignored, because
these panels compute their own attributions from the flow CSV with the
sixteen-class bundle. The signature is unchanged so `MainWindow` needs no
edit.

That method reads three fields off the case — `generated_csv_path`,
`pcap_path`, `pcap_sha256` — and makes the call below on a worker thread.

## The one call

```python
from services.panels_service import build_panels

result = build_panels(
    csv_path,                     # current_case["generated_csv_path"]
    source_name,                  # the PCAP's filename, for display
    finding_index=0,              # which finding to explain
    narrate_with="ollama",        # or None for figures only
    current_pcap=...,             # current_case["pcap_path"]
    current_pcap_sha=...,         # current_case["pcap_sha256"]
    on_progress=say,              # callable(str) -- see "The wait" below
)
```

Returns a dict: `summary`, `findings`, `selected`, `shap`, `recommend` — or
an `error` string to display verbatim. **It never raises for a bad capture.**

## The three panels

| Panel | Key | Built by | What the model adds |
|---|---|---|---|
| 1 Flow summary | `result["summary"]` | `summarise_capture()` | One paragraph over figures the panel already computed. |
| 2 Why this class | `result["shap"]` | `explain_detections()` | One paragraph over the attributions, class name withheld. |
| 3 What to do | `result["recommend"]` | `recommend()` | Ordered steps, each anchored to a line copied from the retrieved playbook. |

Every figure, label and citation is on screen whether or not the model
answered. Narration is **additive**: a missing or broken model degrades a
panel, never empties it.

| File | What it does here |
|---|---|
| `services/panels_service.py` | Builds all three panels. The entry point. |
| `services/narration_service.py` | Prompts, narration, deterministic fallbacks, console reporting. |
| `services/narration_schema.py` | The grounding checks — units, citations, figures, anchors, magnitude, references, direction, decision, mechanism. |
| `services/source_guard.py` | Re-verifies every quoted passage against the PDF it names, on the file as it is now. |
| `services/llm_provider.py` | Ollama and llama.cpp backends. `OLLAMA_MODEL` sets the model. |
| `services/flow_intake.py` | Reads and validates the flow table. |
| `services/config.py`, `session.py` | Paths and per-run workspace. |

## How retrieval works

There is no vector store, no embedding step, no chunking. The classifier has
already named one of sixteen classes, so the right document is known exactly:

1. **class → document.** `KNOWLEDGE_MAP` is a dictionary. An unmapped class
   **raises** rather than falling back to a similar one.
2. **ambiguous pair → a second document**, when the runner-up dominates the
   finding's flows.
3. **result → guidance.** Ten rules with `when(finding, summary)` predicates;
   every match is retrieved. A weak-F1 class pulls `reliability.md`, a flow
   timeout pulls `extraction_validity.md`.
4. **missing files are named, not filled.**
5. **document → shape.** `digest_document()` reduces each file by what it is:
   playbook, explainer or glossary.
6. **quotes → re-verified.** A document whose quotes no longer match its PDF
   is **quarantined** — withheld from the panel *and* the model.
7. **playbooks only reach the prompt.** One helper feeds both the prompt and
   the provenance record, so they cannot disagree.
8. **generation is constrained**, not corrected: the JSON schema has no shape
   for a step without an anchor.
9. **anchors are checked** against the playbook with its headings stripped.
10. **references are derived** from the verified anchor, after the checks.

A recommendation attached to the wrong playbook is worse than none, and a
nearest-neighbour search cannot tell you it picked the wrong one. That is
the whole argument for the lookup.

## The wait, and what to show during it

Narration is nearly all of the wall time:

| | qwen2.5:3b | qwen2.5:7b |
|---|---|---|
| Figures only, no model | 0.4 s | 0.4 s |
| Whole analysis, warm | ~15 s | ~44 s |
| Whole analysis, cold | ~25 s | ~58 s |

So `on_progress` is not decoration. It is called as each stage completes,
with a sentence carrying the finding's own figures:

```
Computing TreeSHAP for Slowloris (133 flows)
Explaining why Slowloris was chosen -- 6 attributions, strongest first
Reading the Slowloris response playbook for what to do next
```

`views/xai_tab.py` appends them in the summary panel and overwrites when the
real summary arrives. A callback that raises cannot fail the analysis.

**Warm the model at tab load.** Ollama loads 4.7 GB on first request and
holds it five minutes; paying that inside the first analysis costs 14 s of
what the investigator waits. `xai_tab.py` does this in the same daemon
thread that warms the source cache.

## What the model is deliberately not told

Each of these was measured, then fixed by changing the **evidence**, not the
instructions. Instructions do not hold at this size; removing the material
does. If you rewrite a prompt, keep these:

- **The class name never reaches panel 2.** Handed it, the model reaches for
  the protocol that class is usually carried over — which a flow record does
  not establish.
- **Cautioned features are withheld entirely.** A feature flagged because the
  model may have learned the lab's service layout is not narrated at all.
  Three attempts at giving it safely all failed; the panel still prints it
  with its caution.
- **Panel 3's worked examples quote no usable sentence.** A rejected example
  is still an example, and the model was seen copying one verbatim.
- **Features sharing an observed value say so** rather than being merged —
  two features with one value can pull in opposite directions, and a combined
  contribution is a number TreeSHAP never produced.

## Console, not the panel

Diagnostics — words the neutraliser cut, each finding with its severity,
which feature was withheld — are **printed**, never rendered. The panel shows
the capture; the console shows the machinery. Keep that split: an
investigator reading a report should not be shown the tool arguing with
itself.

## What is in this folder

Everything this tab loads, and nothing it does not.

```
xai_tab/
├── xai_tab.py
├── README.md                       (this file)
├── models/forenxai/                28 MB
│   ├── XGBoost.pkl                 the estimator
│   ├── scaler.pkl, label_encoder.pkl, features.pkl
│   ├── manifest.json               hashes, checked BEFORE the first load
│   └── shap_global.json
├── artifacts/ForenXAI-Multiclass/xai_tab/
│   └── treeshap_reference.json
└── knowledge/                      100 MB
    ├── incident_response/          16 playbooks, one per class
    ├── interpretability/  datasets/  analyst/  features/
    └── _sources/                   the cited PDFs and their .cache/
```

`BUNDLE_DIR` and `KNOWLEDGE_DIR` resolve here in this folder and to the
repository root in the development tree, so the same code reads both.
`FORENXAI_BUNDLE_DIR` and `FORENXAI_KNOWLEDGE_DIR` override either.

**`models/forenxai/` is not a copy of Tab 1's model.** That one is the
sklearn Pipeline the forensic chain runs; this is the same estimator
serialised without it, beside the scaler, encoder and feature list these
panels need. Each tab loads one and never the other.

**`_sources/` is not optional.** Without the PDFs *and* the `.cache/` beside
them, every quote fails verification and its document is quarantined —
panel 3 then renders with its citations withheld. `manifest.json` is
verified before the first `joblib.load`, because a `.pkl` is executed when
it is loaded.

Shared at the root: `services/` and `sample_data/`. Also needed, and not a
file: `ollama pull qwen2.5:7b` — see `../OLLAMA.md`.

## Tools for this tab

All run from the handoff root, not from this folder:

```bash
python model_ab.py qwen2.5:3b qwen2.5:7b   # score the panels per model
python audit_rag.py                        # source -> retrieval -> panel, all 16 classes
python verify_panels.py sample_data/sample_flows_full.csv
python source_map.py                       # which claim came from which PDF
```

## Check it works

```bash
python smoke_test.py                 # 77 checks, no model needed
python smoke_test.py --llm --ui      # 100, adds narration and the widgets
python test_panels_suite.py          # 166
```

Section **F — INTEGRATION** is the one that matters to a UI: it runs every
renderer against the real service output, so a field rename on either side
fails there instead of surfacing as a blank panel at run time.

## Known open items

Nothing high-severity fires on the sample capture: both models keep 5/5 on
panel 2 across five findings. What remains is medium, and medium means the
phrase is cut or reported, never the paragraph withheld.

- **Adjectives.** The model occasionally writes "relatively short" beside a
  value it was given a comparison for. The neutraliser removes the phrase and
  says so on the console; the figure and its comparison are printed below
  regardless. Roughly one finding in three.
- **Mechanism, rarely.** A protocol name inferred from packet sizes and
  timings, which a flow record does not establish. Caught and reported.
