# knowledge/ — what goes where

Vectorless RAG. No embeddings, no vector store. A condition fires, a named
file is read. Retrieval is a dictionary lookup, so what the panel quotes is
always traceable to a file you can open.

## Hierarchy

```
knowledge/
│
├── _sources/                 * ORIGINALS ONLY. Never edit by hand.
│   ├── *.pdf  *.txt  *.html    Downloaded by fetch_knowledge.py --download.
│   ├── manifest.json           URL + SHA-256 + retrieval date per source.
│   │                           PDFs are gitignored; the manifest is not.
│   └── OWASP_Top10_2025_FULL/  Reference copy of the OWASP guide. Lives
│                               here, NOT in incident_response/, which holds
│                               one file per model class and nothing else.
│                             * A file here that is not registered in
│                               SOURCES in fetch_knowledge.py cannot be
│                               quoted -- --verify has no way to check it.
│
├── incident_response/        * ONE ATTACK CLASS PER FILE. 16 files, one per
│   ├── api.md                  model class including benign.md.
│   ├── benign.md               Answers "what is this traffic, what do I do".
│   ├── bruteforce.md           Filename must match KNOWLEDGE_MAP.
│   ├── ...                     Never put two classes in one file.
│   └── webbased.md
│
├── interpretability/         * HOW TO READ THE MODEL'S OUTPUT.
│   ├── shap_reading.md         Nothing about attacks here. Files answer
│   ├── caveats.md              "how far can I trust this number".
│   ├── confidence.md           Retrieved by RESULT CONDITION, not by class.
│   ├── reliability.md
│   ├── class_ambiguity.md
│   └── glossary.md           * ML terms shown in the UI. Reference only.
│
├── datasets/                 * WHERE THE NUMBERS CAME FROM and where they
│   ├── scope.md                stop being valid. Training scope, transfer
│   └── extraction_validity.md  limits, extractor and timeout effects.
│
├── features/                 * GENERATED. Do not hand-edit.
│   └── glossary.md             Built from config/feature_glossary.py, which
│                               is checked against features.pkl.
│
├── analyst/                  * PROCEDURE, NOT CONTENT. Cross-cutting only:
│   └── triage.md               order of work, mitigation by reversibility,
│                               evidence handling, what not to claim.
│                             * PER-CLASS analyst actions are NOT here. They
│                               live in ANALYST_ACTIONS in panels_service.py
│                               as three short fields per class, because
│                               only the matching row should render and
│                               incident_response/ already carries the
│                               sourced containment advice.
│
├── SOURCES.md                  Every source, what it is used for, how to
│                               check it yourself.
└── REVIEW_GUIDE.md             How to clear a REVIEW REQUIRED draft.
```

## Which file is fetched, and when

Two maps, both in `services/panels_service.py`.

**By class** — `KNOWLEDGE_MAP`. One lookup, always fires.

```
predicted class ── KNOWLEDGE_MAP ── incident_response/<class>.md
runner-up class ── (only when ambiguity flagged) ── its playbook too
```

**By result condition** — `MODEL_GUIDANCE`. Case by case.

| Condition | File |
|---|---|
| always | `interpretability/shap_reading.md` |
| always | `interpretability/caveats.md` |
| always | `datasets/scope.md` |
| always | `analyst/triage.md` |
| class has weak measured F1 | `interpretability/reliability.md` |
| flows below 0.60 confidence | `interpretability/confidence.md` |
| small attack share of a large capture | `interpretability/confidence.md` |
| runner-up dominates the finding | `interpretability/class_ambiguity.md` |
| fallback extractor, or timeout warning | `datasets/extraction_validity.md` |

A file selected by two conditions is read once. Ordering in the panel is
attack guidance first, then a divider, then everything above.

Cost is one file read per condition that fires. Typical finding pulls 5-6
files; a clean finding on a strong class pulls 4.

## Adding a file

1. Put it in the folder whose comment matches what it answers.
2. Give it a provenance header — one `> Source:` line per document it draws
   on, then `> Retrieved: YYYY-MM-DD`. **Without this it renders in the UI
   with no citation.**
3. Quote the source inside `## From <SOURCE_KEY>` using markdown `>`
   blockquotes. Only blockquoted lines are checked; the prose around them is
   yours.
4. Register it: `KNOWLEDGE_MAP` for a class, `MODEL_GUIDANCE` for a
   condition.
5. `python fetch_knowledge.py --verify` — must report 0 problems.

## Rules that are enforced, not conventions

- Every quoted passage must appear verbatim in the source it names.
  `--verify` fails otherwise.
- Every retrieved file must carry an IEEE citation. The test suite fails
  otherwise.
- A class with no `KNOWLEDGE_MAP` entry raises rather than falling back to a
  similar class.
- A draft carrying `REVIEW REQUIRED` fails `--verify`.
- **Every citation must name a source registered in `SOURCES`.** Citing a
  document that is not in `_sources/` means nothing checks it, which is how
  a plausible-looking reference to a book nobody owns reaches a report.

## Status

All 16 class files are reviewed. `--verify` reports 0 problems and 0
warnings: 35 quoted passages traced across the corpus, every file carrying
an IEEE citation.

## Keep files short

Under ~1,500 words. `--verify` warns past that. Long files dilute the answer
and truncate in the local model's context.
