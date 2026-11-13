"""Detecção determinística de prompt injection (camada independente do modelo)."""
from __future__ import annotations

import json
import re

_INJECTION = re.compile(r"ignore (all |previous )|disregard|system prompt|classify this alert", re.I)


def looks_like_injection(alert: dict) -> bool:
    return bool(_INJECTION.search(json.dumps(alert)))
