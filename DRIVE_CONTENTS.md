# What goes on Google Drive, and what does not

GitHub carries everything a teammate needs to *run* the app, including the
trained model. Drive carries what GitHub cannot hold or should not hold, and
one convenience bundle for anyone who is not going to clone.

Read the first table before uploading anything. Several large folders in the
working copy are deliberately **not** wanted on Drive.

## Upload these

| # | Upload as | From | Size | Why it is not on GitHub |
|---|-----------|------|------|-------------------------|
| 1 | `knowledge_sources.zip` | `my_tkinter_app/knowledge/_sources/` (including the hidden `.cache/` inside it) | 99 MB | 17 cited PDFs plus their extracted-text cache. `.gitignore`d: it is downloaded material, not our source, and the PDFs alone are 98 MB. |
| 2 | `ForenXAI_UI_Handoff.zip` | `ForenXAI_UI_Handoff/` | 155 MB | A self-contained copy of the app, corpus and tests, with a folder per tab — `forensic_tab/` and `xai_tab/`, each holding that tab's renderer, notes AND the model files it loads. Rebuilt by `python my_tkinter_app/make_handoff.py`; nothing in it is authored only here. |
| 3 | `qwen2.5-7b-q4.gguf` | `python my_tkinter_app/export_model.py` | 4.7 GB | **Only for a packaged build.** Anyone with Ollama runs `ollama pull qwen2.5:7b` instead and never needs this file. Ollama keeps its weights in a content-addressed blob store, so there is no `.gguf` on disk until you export one — and a copied blob store does not register with Ollama. |
| 4 | `cicflowmeter_v4/` + `jdk8/` installers | wherever you downloaded them | ~200 MB | pip cannot install either. `my_tkinter_app/requirements.txt` explains both. Optional — the pure-Python PCAP fallback runs without them. |
| 5 | `sample_captures/` | your `.pcap` / `.pcapng` test files, plus `my_tkinter_app/sample_data/sample_flows_full.csv` | varies | Test input, not code. The 721 KB full flow table is `.gitignore`d; the 653 KB `sample_flows.csv` is already on GitHub. |

**Item 1 matters most.** Without `_sources/`, `source_guard` cannot verify a
single quoted passage, so every knowledge document is quarantined and panel 3
renders with its citations withheld. `python fetch_knowledge.py` re-downloads
them, but that depends on 17 URLs still resolving. The zip is the insurance.

Keep `.cache/` inside the zip. It is 8 MB of extracted text, it is what
`source_guard` actually reads, and with it present verification of the whole
corpus takes 0.68 ms instead of re-parsing PDFs.

## Do not upload these

| Folder | Size | Where it comes from instead |
|--------|------|------------------------------|
| `my_tkinter_app/models/` | 28 MB | **Already on GitHub.** `XGBoost.pkl` is 27 MB, under GitHub's 100 MB limit. Do not duplicate it to Drive — a second copy is how the two drift apart. |
| `my_tkinter_app/artifacts/` | 54 MB | **Already on GitHub**, same reasoning. Six `.joblib` models, largest 27 MB. |
| `my_tkinter_app/Top10/` | 564 MB | A clone of `github.com/OWASP/Top10`. Re-clone it if you need to re-derive the OWASP corpus file; the derived file is on GitHub. |
| `my_tkinter_app/ForenXAI_Cases/` | 37 MB | Leftover case output from before runs moved to a temp workspace. Delete it. |
| Ollama's blob store | 4.7 GB | `ollama pull qwen2.5:7b`. Copying the store does not register the model. The **exported `.gguf`** (item 3) is a different thing and is only needed by a packaged build. |
| `__pycache__/`, `*.pyc` | — | Regenerated on first run. |

## What a new member does

1. `git clone https://github.com/CopingMoa/ForenXAI-v2.git`
2. `py -3.11 -m pip install -r requirements.txt`
3. Download **item 1** from Drive, unzip into `my_tkinter_app/knowledge/` so the
   path is `my_tkinter_app/knowledge/_sources/`.
4. `ollama pull qwen2.5:7b` (4.7 GB — the default; `qwen2.5:3b` is the
   fallback for a slower machine, see `handoff_docs/OLLAMA.md`)
5. `cd my_tkinter_app && python smoke_test.py` — expect **122/122**.
   `python smoke_test.py --llm --ui` runs the narration and Tk checks too: **154/154**.

Someone who only needs to *look* at the app can skip 1-3 and take item 2
instead; it already contains the corpus, the models and the tests.

## Before you upload item 2

```bash
cd my_tkinter_app
python make_handoff.py     # build
python preflight.py        # then prove it survives being sent
```

`preflight.py` checks the things that break between building a folder and
someone else unzipping it: a corpus that verifies against nothing because the
cache was pruned, a model file that never made it, a quote that has drifted
from its PDF, bytecode that should not travel. It ends in **Ready to send** or
names what failed. Every check in it failed at least once during development.

## Keeping Drive current

Re-upload item 1 when `fetch_knowledge.py` gains a source, and item 2 after any
change to `my_tkinter_app/`. The bundle carries no version stamp, so name the
file with the date you built it.
