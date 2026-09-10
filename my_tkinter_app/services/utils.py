import os
import hashlib
from datetime import datetime, timezone


def utc_timestamp():
    return datetime.now(timezone.utc).isoformat()


def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def safe_filename(path):
    return os.path.basename(path)


def resource_dir(base, *candidates, env=None):
    """First of `candidates` that exists under `base`, else the last one.

    Two layouts have to work from the same code.

    In this repository the data sits in one place per kind -- models/,
    knowledge/, artifacts/ -- because one application reads all of it.

    In the folder make_handoff.py builds, it is split by TAB: the forensic
    tab's model.joblib under forensic_tab/, the XAI tab's .pkl bundle and
    knowledge corpus under xai_tab/. Someone handed that folder is working
    on one tab, and what that tab needs should be in front of them rather
    than three directories away.

    Falling back to the last candidate rather than raising keeps the error
    where it belongs: the loader that opens the file reports a missing
    model far better than a path helper can at import time.

    `env` names a variable that overrides both, for a deployment that puts
    the data somewhere else entirely.
    """
    if env:
        override = os.environ.get(env)
        if override:
            return override
    for c in candidates:
        path = os.path.join(base, *c) if isinstance(c, tuple) else \
            os.path.join(base, c)
        if os.path.exists(path):
            return path
    last = candidates[-1]
    return os.path.join(base, *last) if isinstance(last, tuple) else \
        os.path.join(base, last)
