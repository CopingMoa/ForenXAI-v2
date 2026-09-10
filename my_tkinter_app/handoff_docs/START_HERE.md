# Start here

Two tabs. **Each has its own folder, holding its notes and every model file
it loads.** Open the one you are working on.

| | |
|---|---|
| **[`forensic_tab/`](forensic_tab/README.md)** | PCAP → flows → prediction → SHAP → case files. One call: `run_forensic_pipeline()`. Produces the evidence. |
| **[`xai_tab/`](xai_tab/README.md)** | Flow table → three explanation panels. One call: `build_panels()`. Explains it. |

The two meet at one field. Tab 1 writes `current_case["generated_csv_path"]`
and Tab 2 reads it.

**Everything both tabs load is in this folder.** Verified on the build, not
assumed: Tab 1's Pipeline loads and reports 16 classes; Tab 2 builds all
three panels with no language model at all — 15 findings, TreeSHAP
additivity 1.2e−06, 14 retrieved sections, every reference resolving, zero
quarantined and zero missing documents.

**One thing is not a file, and one is optional.** The language model is a
registry pull (`ollama pull qwen2.5:7b`), and a `.gguf` on disk is needed
only if you package with PyInstaller. CICFlowMeter v4 is optional. Both are
covered below.

---

## What is in each tab folder

```
forensic_tab/                                   28 MB
├── README.md                    the notes for this tab
├── forensic_tab.py              the renderer
└── artifacts/ForenXAI-Multiclass/forensic_tab/
    ├── model.joblib             the XGBoost estimator, wrapped in a
    │                            Pipeline that scales its own input
    └── frozen_feature_schema_l2.json

xai_tab/                                       127 MB
├── README.md                    the notes for this tab
├── RAG_INTEGRATION.md           what retrieval returns, and what not to do to it
├── UI_BACKEND_MAP.md            every widget in BOTH tabs → the field behind it
├── OLLAMA.md                    the local language model: install and choice
├── xai_tab.py                   the renderer
├── models/forenxai/             the same XGBoost, serialised for these panels
│   ├── XGBoost.pkl              the estimator
│   ├── scaler.pkl               the space the trees split on
│   ├── label_encoder.pkl        class names — read from here, never a literal
│   ├── features.pkl             feature ORDER. Misalignment here is the
│   │                            dangerous bug: it fails silently
│   ├── shap_global.json         per-class typical drivers, whole test set
│   └── manifest.json            hashes, checked before any pickle is opened
├── artifacts/ForenXAI-Multiclass/xai_tab/
│   └── treeshap_reference.json  the reference TreeSHAP output
└── knowledge/                   the retrieval corpus — 26 documents
    ├── incident_response/       16 playbooks, one per class
    ├── interpretability/        how to read an attribution
    ├── datasets/ analyst/ features/
    └── _sources/                18 cited sources, and the extracted-text
                                 .cache/ every quote is verified against
```

**The two model files are not duplicates.** Tab 1 loads the sklearn
Pipeline; Tab 2 loads the same estimator without it, beside the scaler,
encoder and feature list those panels need. Each tab loads one and never
the other, so splitting them by tab copies nothing twice.

## What is shared, and why it is not in either folder

```
services/            15 modules, 350 KB, imported by both tabs
sample_data/         a 1,500-flow table, so everything runs before you
                     have a PCAP of your own
```

`services/` is where the analysis lives — no rendering, so it tests without
a display. Two copies of a module is how they drift, so there is one.

The scripts below sit at the root because they import `services` and read
`sample_data`, and both resolve from here.

| Script | Belongs to | What it does |
|---|---|---|
| `smoke_test.py` | both | 122 checks, no model needed. **Run this first.** |
| `test_panels_suite.py` | both | 162 checks, the detailed suite |
| `preflight.py` | both | what the sender ran before this reached you |
| `audit_rag.py` | xai_tab | source → retrieval → panel, all 16 classes |
| `model_ab.py` | xai_tab | scores the panels per language model |
| `verify_panels.py` | xai_tab | recomputes every panel figure independently |
| `source_map.py` | xai_tab | which claim came from which PDF |
| `build_exe.py` | both | packages the application. Read its header first |
| `export_model.py` | xai_tab | copies the local LLM out of Ollama as a `.gguf` |
| `fetch_knowledge.py` | xai_tab | rebuilds the corpus from its sources |
| `deploy_multiclass_model.py` | — | how the bundle was produced. Reference |

## Setting up

```bash
py -3.11 -m pip install -r requirements.txt
ollama pull qwen2.5:7b            # the local model — see xai_tab/OLLAMA.md
python smoke_test.py              # expect 122/122
python smoke_test.py --llm --ui   # 154/154, adds narration and the widgets
```

Only `xai_tab/` needs the language model. Tab 1 never calls one.

**The one thing that must not be missing:** `xai_tab/knowledge/_sources/`
holds the cited PDFs *and* a hidden `.cache/`. Without them every quote
fails verification, every document is quarantined, and panel 3 renders with
its citations withheld. `preflight.py` refuses to clear a build that lost
them.

## Where the language model file goes

Running from source, you do not need one — `ollama pull` is enough, and
Ollama keeps its weights in its own store.

Packaging with PyInstaller, you do: the packaged app loads a real `.gguf`
path, and Ollama has no such file.

```bash
python export_model.py --out xai_tab/models     # 4.7 GB, lands beside the .pkl
python build_exe.py                             # then package
```

`make_handoff.py --with-model` does the export as part of the build.

## What is not in this folder

| | Why | How to get it |
|---|---|---|
| The language model | 4.7 GB, and a registry pull rather than a file | `ollama pull qwen2.5:7b` |
| CICFlowMeter v4 + JDK 8 | pip cannot install either. **Optional** — a pure-Python extractor takes over | installers, from the team Drive |
| Your own PCAPs | test evidence, not code | your captures |

`SEND_LIST.md` is the complete file inventory, generated from this folder by
`preflight.py` rather than written by hand.
