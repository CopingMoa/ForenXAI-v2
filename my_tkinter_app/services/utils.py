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
