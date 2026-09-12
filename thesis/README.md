# Chapter 3

The methodology chapter, and the revision built against the code rather than
against memory.

| File | What it is |
|---|---|
| `Chapter 3.pdf` | The chapter as received. The baseline every correction is measured from. |
| `ch3_extracted.txt` | Its text, extracted page by page. What the revision was diffed against. |
| `Chapter3_revision.md` | The revision. Drafted sections, corrected tables, and the three architecture figures in Mermaid. |
| `Chapter3_revision.docx` | The same, rendered Times New Roman 12 pt double-spaced so sections paste straight into the manuscript. |
| `mk_docx.py` | Rebuilds the `.docx` from the `.md`. Run it from this directory. |

```bash
cd thesis && python mk_docx.py
```

## Where the numbers come from

Every figure in the revision traces to a file in one of two trees:

- **`forenxai_binary/`** (the pipeline, on Drive) — `scripts/00` through `scripts/15`
  for the procedures, `src/schema.py` for the naming and alignment claims,
  `results/tables/` and `results/*/[model]_internal.json` for every reported
  number, and `logs/` for the dataset distributions.
- **`my_tkinter_app/`** (this repo) — `services/panels_service.py`,
  `shap_service.py`, `source_guard.py` and `narration_schema.py` for §3.4 and
  the explanation-quality metrics in §3.6.

The section-by-section mapping is the evidence map:
https://claude.ai/code/artifact/3ecefe1b-9aab-4364-9d66-76c8960a7161

## The one figure that is still unsourced

§3.2 and Table 3 report **13,390,249** benign flows in CSE-CIC-IDS2018. That
number appears in no log, no results file and no run. All five executions of
`01_prepare_cicids2018.py` logged **13,484,708**. The 95,760 difference falls
entirely in Benign, Infiltration and Bruteforce and is exactly zero elsewhere,
which is what row-level cleaning would look like — but no artifact demonstrates
it. Either find the source or use the logged figure and cite the log.

## Before submission

The three figures in §3.4 are Mermaid. Render them to image; Mermaid does not
survive a Word paste.
