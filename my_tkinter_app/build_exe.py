"""
build_exe.py -- package the application with PyInstaller.

    python build_exe.py                 build into dist/
    python build_exe.py --out DIR       somewhere else
    python build_exe.py --with-model    bundle the .gguf too (+4.7 GB)

Run it, do not reconstruct the flags. Every one of them is here because
the build failed without it, and three of the failures happen at RUN time
rather than build time -- the worst moment to find them.

WHAT THE FIRST BUILD TAUGHT

1. `--collect-all xgboost` fails outright. Collecting submodules imports
   xgboost.testing, which does `pytest.importorskip("hypothesis")` and
   raises. Collect its binaries and data instead and skip the walk.

2. Nothing is bundled unless you say so. The data roots resolve off
   __file__, which in a frozen build points inside the unpacked bundle, so
   models/, artifacts/ and knowledge/ have to be there -- and --add-data
   source paths resolve relative to the SPEC directory, not the working
   directory, so they are absolute here.

3. services.model_input is imported by nothing. It exists so a
   FunctionTransformer inside model.joblib can be pickled by import path,
   which means joblib imports it at UNPICKLE time. PyInstaller's static
   analysis cannot see that, so the build succeeded, launched, and failed
   with "No module named 'services.model_input'" the moment a model was
   loaded. That module's own docstring predicted this.

The output is about 6 GB with the corpus and 1.5 GB without. Most of it is
sklearn, shap and llama_cpp binaries.
"""
import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

DATA = [
    ("models", "models"),
    ("artifacts/ForenXAI-Multiclass", "artifacts/ForenXAI-Multiclass"),
    ("knowledge", "knowledge"),
    ("sample_data", "sample_data"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(HERE, "dist"))
    ap.add_argument("--work", default=os.path.join(HERE, "build"))
    ap.add_argument("--with-model", action="store_true",
                    help="bundle the exported .gguf as well (+4.7 GB)")
    args = ap.parse_args()

    cmd = [
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--name", "ForenXAI",
        "--distpath", args.out, "--workpath", args.work, "--specpath", args.work,

        # (1) The submodule walk imports xgboost.testing, which raises.
        "--collect-binaries", "xgboost", "--collect-data", "xgboost",
        "--exclude-module", "xgboost.testing", "--exclude-module", "pytest",

        # These three ship compiled extensions PyInstaller does not find on
        # its own, and tkinterdnd2 ships a Tcl package as data.
        "--collect-all", "shap",
        "--collect-all", "sklearn",
        "--collect-all", "llama_cpp",
        "--collect-all", "tkinterdnd2",

        # (3) Reached only through joblib's unpickling. Nothing imports it.
        "--hidden-import", "services.model_input",
    ]

    # (2) Absolute sources: --add-data resolves them against --specpath.
    for src, dst in DATA:
        full = os.path.join(HERE, src)
        if os.path.isdir(full):
            cmd += ["--add-data", f"{full}{os.pathsep}{dst}"]
        else:
            print(f"  SKIP (missing)  {src}")

    if args.with_model:
        from services.llm_provider import OLLAMA_MODEL
        gguf = os.path.join(HERE, "models",
                            f"{OLLAMA_MODEL.replace(':', '-')}-q4.gguf")
        if os.path.isfile(gguf):
            cmd += ["--add-data", f"{gguf}{os.pathsep}models"]
        else:
            print(f"  --with-model, but {os.path.basename(gguf)} is not in "
                  f"models/. Run export_model.py first.")
            return 1

    cmd.append(os.path.join(HERE, "main.py"))

    print("Building ForenXAI")
    print("-" * 60)
    rc = subprocess.run(cmd, cwd=HERE).returncode
    if rc != 0:
        print("\nBuild FAILED.")
        return rc

    exe = os.path.join(args.out, "ForenXAI", "ForenXAI.exe")
    print(f"\nBuilt  {exe}")
    print("\nRUN IT BEFORE YOU SHIP IT. The build succeeding proves very")
    print("little: two of the three failures this script encodes happened")
    print("at launch, and one of them only when a model was loaded.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
