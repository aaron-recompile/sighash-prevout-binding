"""
Load KEY=VALUE pairs from a `.env` file in the repository root into os.environ
(only keys that are not already set). Optional convenience: lets you keep
CAT_DEMO_WIF and INQUISITION_* in a gitignored `.env` instead of exporting them.
"""
from __future__ import annotations

import os
from pathlib import Path

_ROOT_ENV = Path(__file__).resolve().parent / ".env"


def load_dotenv_files() -> None:
    if not _ROOT_ENV.is_file():
        return
    try:
        text = _ROOT_ENV.read_text(encoding="utf-8")
    except OSError:
        return
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        if key and key not in os.environ:
            os.environ[key] = val.strip().strip('"').strip("'")


load_dotenv_files()
