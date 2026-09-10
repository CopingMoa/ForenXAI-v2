"""
export_model.py -- copy the local model out of Ollama as a plain .gguf file.

    python export_model.py                    export OLLAMA_MODEL
    python export_model.py qwen2.5:3b         export a specific model
    python export_model.py --out DIR          somewhere other than models/

WHY THIS EXISTS
Ollama keeps its weights in a content-addressed blob store, so there is no
file called qwen2.5-7b-q4.gguf anywhere on the machine -- only
blobs/sha256-2bada8a7... with no extension. Two consequences:

  * You cannot hand someone the model by copying a folder. `ollama pull`
    is a registry operation, and a copied blob store does not register.
  * LlamaCppProvider, which is what a PyInstaller build loads, wants a
    real .gguf path. Without this step the packaged application has no
    model at all.

This reads the FROM line out of `ollama show --modelfile`, which is the
blob Ollama itself resolves the tag to, and copies it under the name
llm_provider derives from OLLAMA_MODEL. That is the whole job: no
conversion, no re-quantisation, byte-identical weights.

The exported file is 4.7 GB for 7b and 1.9 GB for 3b, which is why
make_handoff.py leaves it out by default -- see --with-model there.
"""
import argparse
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def blob_for(tag):
    """The blob file Ollama resolves this tag to, or None with a reason."""
    try:
        r = subprocess.run(["ollama", "show", tag, "--modelfile"],
                           capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        return None, "ollama is not on PATH"
    except subprocess.TimeoutExpired:
        return None, "ollama did not respond within 60 s"

    if r.returncode != 0:
        return None, (r.stderr.strip().splitlines() or ["unknown error"])[-1]

    # The first uncommented FROM is the weights. Later FROM lines in a
    # Modelfile can name adapters, so the comment filter matters.
    for line in r.stdout.splitlines():
        if line.startswith("#"):
            continue
        m = re.match(r"\s*FROM\s+(.+?)\s*$", line)
        if m and os.path.isfile(m.group(1)):
            return m.group(1), ""
    return None, f"no FROM line in `ollama show {tag} --modelfile` named a file"


def export(tag, out_dir):
    from services.llm_provider import OLLAMA_MODEL          # noqa: E402

    tag = tag or OLLAMA_MODEL
    # The name LlamaCppProvider derives from the same variable, so the
    # export and the loader cannot disagree about what the file is called.
    name = f"{tag.replace(':', '-')}-q4.gguf"
    dest = os.path.join(out_dir, name)

    src, why = blob_for(tag)
    if not src:
        print(f"FAILED  {tag}: {why}")
        print("        Pull it first:  ollama pull " + tag)
        return 1

    size = os.path.getsize(src)
    if os.path.isfile(dest) and os.path.getsize(dest) == size:
        print(f"already exported  {name}  ({size / 1e9:.1f} GB)")
        return 0

    os.makedirs(out_dir, exist_ok=True)
    print(f"exporting {tag}")
    print(f"  from  {src}")
    print(f"  to    {dest}")
    print(f"  {size / 1e9:.1f} GB -- this takes a minute or two")
    shutil.copy2(src, dest)

    got = os.path.getsize(dest)
    if got != size:
        print(f"FAILED  copied {got} bytes of {size}")
        return 1
    print(f"done  {name}  ({got / 1e9:.1f} GB)")
    print()
    print("The packaged build loads this path; Ollama does not need it and")
    print("keeps using its own blob. Ship it beside the handoff, not inside")
    print("it, unless you have somewhere that takes a 5 GB upload.")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("tag", nargs="?", default=None,
                    help="model tag; defaults to OLLAMA_MODEL")
    ap.add_argument("--out", default=os.path.join(HERE, "models"))
    a = ap.parse_args()
    sys.exit(export(a.tag, a.out))
