# Local LLM (Ollama) — optional

Narration is **off by default and the panels are complete without it.**
Skip this file entirely if you are not wiring it up; nothing else depends
on it.

## Why local and not an API

The model reads flow records from evidence captures. Sending those to a
third-party API sends the evidence with them. Everything runs on the
analyst's machine for that reason, not for cost.

## Setup

```bash
# 1. Install Ollama:  https://ollama.com/download
# 2. Pull the model (~4.7 GB):
ollama pull qwen2.5:7b
# 3. Ollama serves on localhost:11434 automatically. Check:
curl http://localhost:11434/api/tags
```

## Use

```python
result = build_panels(csv_path, source_name, narrate_with="ollama")
```

Narration lands in each panel under `["narration"]`. Absent means it was not
requested or the model was unreachable — render the panel either way.

By default only panels 1 and 2 are narrated. Panel 3 quotes response
documents verbatim with their citations, and a quote cannot be improved by
rewriting it. To include it:

```python
from services.narration_service import ALL_PANELS
build_panels(csv_path, name, narrate_with="ollama", narrate_panels=ALL_PANELS)
```

## Configuration

| Variable | Default |
|---|---|
| `OLLAMA_URL` | `http://localhost:11434` |
| `OLLAMA_MODEL` | `qwen2.5:7b` |

`qwen2.5:3b` is the fallback for a slower machine: about four times faster
(5 s a panel against 20 s) and about 2 GB smaller. It costs accuracy on
panel 2, which is the panel making claims about the training distribution.
Over five runs on one finding, 3b made six magnitude claims the supplied
comparison contradicts or never supported; 7b made one. Panels 1 and 3 are a
tie. Nothing in the code needs changing to swap — set the variable.

Measure it yourself before trusting either:

```bash
RUNS=5 python model_ab.py qwen2.5:3b qwen2.5:7b
```

## Expect it to be slow

About 20 seconds per panel on CPU. **Run it off the UI thread.** The
reference implementation polls a `queue.Queue` from the main thread —
calling `widget.after()` from a worker raises
`RuntimeError: main thread is not in main loop`.

Show the figures immediately and fill narration in when it arrives. Do not
block the panel on it.

## Narration is checked before it is shown

`services/narration_schema.py` compares the generated text against what the
model was given and flags:

- a log-odds value written as a percentage (`units`)
- a citation that was never supplied (`citation`)
- figures absent from the input (`figures`)

```python
findings = result["summary"]["narration"]["findings"]
if findings:
    show_warning("Read the figures below, not the prose.")
```

The prose is never the source of truth. Every figure, label and citation is
on screen whether narration ran or not.

## Do not fine-tune it

The checks above catch the failure mode that matters. Fine-tuning changes
style and format, not factual grounding, so it would not remove a single one
of those checks. If narration reads badly, adjust the prompt and the
`MAX_TOKENS` cap in `narration_service.py` first.

## Packaging with PyInstaller

Ollama is a separate process and cannot be bundled. For a single-file build
use the `llama-cpp-python` provider instead — see the module docstring in
`services/llm_provider.py`, which documents extracting the GGUF from
Ollama's blob store.

```bash
pyinstaller --collect-all xgboost --collect-all shap \
            --collect-all sklearn --collect-all llama_cpp app.py
```

Untested as of this handoff.
