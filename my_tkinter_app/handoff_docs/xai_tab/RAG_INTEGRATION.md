# Implementing retrieval in a UI

You do not implement retrieval. It runs inside `build_panels()` and hands you
a dict. This document says which files must be present for that to work, what
comes back, and what you are responsible for rendering.

If you only read one thing: **retrieval has already happened by the time you
have the dict.** Your job is to display what it produced without weakening
the guarantees it carries.

---

## 1. The files that must be present

Nothing here is optional. Each line says what breaks without it.

```
xai_tab/
├── knowledge/                          THE CORPUS
│   ├── incident_response/*.md            16 playbooks, one per class
│   ├── interpretability/*.md             SHAP, confidence, reliability, ambiguity
│   ├── datasets/*.md                     scope and extraction-validity guidance
│   ├── analyst/triage.md                 ordering guidance
│   ├── features/glossary.md              74 features in plain English
│   └── _sources/                         THE CITED PDFs
│       ├── *.pdf                           what every quote is checked against
│       ├── manifest.json                   which source each file came from
│       └── .cache/                         extracted text, content-addressed
└── models/forenxai/                    the classifier the findings come from
```

Without `knowledge/` there is nothing to retrieve. Without `_sources/` —
**PDFs and the hidden `.cache/` together** — every quote fails verification,
every document is quarantined, and panel 3 renders with its citations
withheld. The cache is 8 MB and is what the verifier actually reads; the PDFs
are 98 MB and are what makes the cache checkable. Ship both.

```
services/
├── panels_service.py       build_panels() — the entry point. Holds the three
│                           retrieval tables: KNOWLEDGE_MAP (class → document),
│                           AMBIGUOUS_PAIRS (runner-up → second document),
│                           MODEL_GUIDANCE (10 result-conditioned rules).
│                           Also digest_document() and recommend().
├── source_guard.py         verify_sections() re-checks every quoted passage
│                           against the PDF it names. repair_document() is the
│                           only writer. Omit this file and the panels render
│                           with no check behind the quotes.
├── narration_service.py    prompts, narrate(), narrate_all(), the JSON schema,
│                           and the deterministic fallback for every panel.
├── narration_schema.py     the grounding checks: units, citations, figures,
│                           anchors, magnitude, references, direction, decision,
│                           mechanism. This is what decides whether prose is
│                           shown, edited or withheld.
├── llm_provider.py         Ollama and llama.cpp behind one call. OLLAMA_MODEL
│                           selects the model; nothing else needs changing.
├── flow_intake.py          reads and validates the flow table
├── config.py, session.py   paths and the per-run workspace
└── utils.py                hashing, and the two-layout path resolver
```

Plus `fetch_knowledge.py` at the root — `source_guard` reads every source path
through it, so it is not optional either, and the two must agree on the corpus
directory. Smoke section **R** asserts exactly that.

## 2. The call

```python
from services.panels_service import build_panels

result = build_panels(
    csv_path,                  # current_case["generated_csv_path"]
    source_name,               # the PCAP's filename, for display
    finding_index=0,           # which finding to explain
    narrate_with="ollama",     # or None for figures only
    current_pcap=...,          # current_case["pcap_path"]
    current_pcap_sha=...,      # current_case["pcap_sha256"]
    on_progress=say,           # callable(str), optional
)
```

Returns `summary`, `findings`, `selected`, `shap`, `recommend` — or an
`error` string to display verbatim. **It never raises for a bad capture.**

Run it on a worker thread. It takes 44 s warm and 58 s cold on `qwen2.5:7b`,
against 0.4 s with `narrate_with=None`.

## 3. What retrieval hands you, and what to do with it

Everything below is on `result["recommend"]`.

| Key | Type | What it is | What you must do |
|---|---|---|---|
| `class` | str | the finding's class | heading |
| `sections` | list | the retrieved, digested, verified documents | render in order — see below |
| `citations` | list of str | file paths that were actually retrieved | not for display; use `references` |
| `references` | list of str | full ACM-format citations | the reference list under the panel |
| `reference_map` | list of `{n, citation}` | maps a `[n]` marker to its citation | resolve markers; a marker with no entry is a bug, not a style choice |
| `ambiguity` | str or None | why two classes cannot be separated | **show it when present** — it is the model saying it does not know |
| `model_guidance` | list of str | which guidance rules fired | optional, useful in a detail view |
| `missing_documents` | list | mapped but absent from disk | say which guidance is unavailable; substitute nothing |
| `unverified_documents` | list | quarantined — quotes no longer match their PDF | show the banner and offer repair; **do not render their content** |
| `evidence` | list | top 3 attributions from panel 2 | the "why" beside the "what to do" |

### Each entry in `sections`

| Field | Meaning |
|---|---|
| `heading` | render as the section title |
| `body` | the digested text, already reduced from the full document |
| `kind` | `playbook`, `explainer` or `glossary` — style it differently if you like |
| `source` | the file it came from |
| `citations` | which references this section supports |
| `quotes_verified` | how many quoted passages were checked |
| `verified_against` | `"source"` (the PDF itself) or `"cache"` (extracted text) |
| `panel` | which panel the section belongs to, when it is guidance |

**`verified_against` is a claim about evidence strength and must reach the
screen.** `"source"` means the quote was matched against the PDF on disk;
`"cache"` means against extracted text whose filename carries its hash — the
recipient still knows which document, but cannot re-derive it themselves. Do
not collapse the two into one tick mark.

## 4. What you must not do

- **Do not re-order or merge `sections`.** Order is triage order.
- **Do not render a document listed in `unverified_documents`.** It is
  quarantined because its quotes drifted from the source; showing it is the
  one failure the whole verification chain exists to prevent.
- **Do not write your own `[n]` markers.** They are derived from verified
  anchors after the checks run. A marker you invent points at nothing.
- **Do not hide `ambiguity` because it makes the output look uncertain.**
  Slowloris and DoS correlate at 0.90 on SHAP importance. A confident single
  answer there is the wrong answer.
- **Do not show the grounding findings.** They are printed to the console on
  purpose. The panel shows the capture; the console shows the machinery.

## 5. Prove it works in your tree

```bash
python smoke_test.py           # 100 checks, no model needed
python smoke_test.py --llm     # adds narration
python smoke_test.py --ui      # adds the Tk widgets
python audit_rag.py            # source → retrieval → panel, all 16 classes
```

Section **F — INTEGRATION** runs every renderer against real service output,
so a field rename on either side fails there rather than surfacing as a blank
panel at run time. Section **R — LAYOUT** proves the corpus resolves in
whichever folder layout your copy is in.

If `smoke_test.py` passes and `audit_rag.py` reports no missing documents,
retrieval is working and the rest is rendering.
