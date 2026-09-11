# Messages to paste

Three blocks. Send the first to everyone, then the relevant one to each
team. They are the chat-window version of the three READMEs — not a
replacement for them, a way in.

The check counts below are from the build these were written against. **If
someone reports a different number, they do not have this folder.**

---

## 1 — to everyone

```
ForenXAI handoff — unzip it, then read START_HERE.md.

The zip should be ~95 MB. If it's smaller, something was dropped in
transit — tell me before you use it.

Setup (both teams):
    py -3.11 -m pip install -r requirements.txt
    python smoke_test.py            → must print 122/122

If that passes, the folder is intact and you can start.

Layout:
    START_HERE.md      the map — read first
    forensic_tab/      Tab 1's notes + the model it loads
    xai_tab/           Tab 2's notes + its model, and the knowledge corpus
    services/          shared code, imported by both tabs
    sample_data/       a 1,500-flow table, so everything runs before
                       you have a PCAP of your own

Each tab folder already contains every file that tab loads. Nothing to
download except the language model, and only Tab 2 needs that.
```

---

## 2 — to the forensic tab people

```
Your folder: forensic_tab/     Your notes: forensic_tab/README.md

    py -3.11 -m pip install -r requirements.txt
    python smoke_test.py            → 122/122

That's your whole setup. No language model, no corpus — you never touch
ollama or xai_tab/knowledge/.

Already in your folder:
    artifacts/.../model.joblib                 the classifier
    artifacts/.../frozen_feature_schema_l2.json the column order
    forensic_tab.py                            a working renderer (reference)

Write against ONE call:
    from services.pipeline_service import run_forensic_pipeline
    current_case, shap_results = run_forensic_pipeline(
        pcap_path, model, model_name, case_output_dir,
        log_fn, on_metrics_ready)

Run it on a worker thread — it blocks for tens of seconds. Marshal every
widget update back through root.after; Tk is not thread-safe and fails
intermittently, not loudly.

It returns current_case with 19 keys. Six are path+hash pairs. SHOW THE
HASHES — they're why the analysis can be repeated.

You hand off to Tab 2 with one method:
    xai_tab.update_xai_results(current_case, shap_results)

Optional: CICFlowMeter v4 + JDK 8. Without them a Python extractor takes
over automatically — but the UI must say which one ran (it's in
flow_extraction.json beside the CSV).

Field-by-field widget contract: xai_tab/UI_BACKEND_MAP.md (covers both tabs).
```

---

## 3 — to the XAI tab people

```
Your folder: xai_tab/     Your notes: xai_tab/README.md

    py -3.11 -m pip install -r requirements.txt
    ollama pull qwen2.5:7b          → 4.7 GB, see xai_tab/OLLAMA.md
    python smoke_test.py            → 122/122, no model needed
    python smoke_test.py --llm --ui → 154/154, adds narration + widgets
    python audit_rag.py             → retrieval, all 16 classes

Already in your folder:
    models/forenxai/          classifier, scaler, encoder, feature order
    artifacts/.../treeshap_reference.json
    knowledge/                26 docs, 16 playbooks, _sources/ with the
                              cited PDFs AND a hidden .cache/
    xai_tab.py                a working renderer (reference)

Write against ONE call:
    from services.panels_service import build_panels
    result = build_panels(csv_path, source_name, finding_index=0,
                          narrate_with="ollama",
                          current_pcap=..., current_pcap_sha=...,
                          on_progress=say)

Worker thread: 44 s warm, 58 s cold — against 0.4 s with
narrate_with=None. Use on_progress or the window looks hung.

Returns: summary, findings, selected, shap, recommend — or an "error"
string to show verbatim. It never raises for a bad capture.

READ xai_tab/RAG_INTEGRATION.md BEFORE RENDERING PANEL 3.
You do not implement retrieval — it already happened by the time the call
returns. That file lists what comes back and the five things not to do.

Four rules you can't guess from a field name:
  - attributions[].contribution is LOG-ODDS. Never label it a percentage.
  - Colour bars by .direction, not by the sign.
  - verified_against "source" vs "cache" are different claims — don't
    collapse them into one tick.
  - Never render a document listed in unverified_documents.

KEEP _sources/ WHOLE — the PDFs and the hidden .cache/. Verification
needs at least one of the two: with both, quotes verify against the PDF;
with only the cache, they verify against extracted text and the panel
says so. Lose BOTH and every document is quarantined. Run preflight.py if
you want that checked.

Field-by-field widget contract: xai_tab/UI_BACKEND_MAP.md.
```
