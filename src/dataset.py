from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_PATH = ROOT / "data" / "incident.json"


def load() -> dict:
    return json.loads(DATA_PATH.read_text())
