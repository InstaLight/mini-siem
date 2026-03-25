"""Load agent JSON config; merge with defaults."""
from __future__ import annotations

import json
import os
from typing import Any


DEFAULTS: dict[str, Any] = {
    "server_host": "127.0.0.1",
    "server_port": 9001,
    "reconnect_delay_seconds": 5,
    "send_retry_seconds": 2,
    "agent": {
        "id": "mini-siem-agent",
        "hostname": None,
        "os": None,
        "ip": None,
    },
}


def load_config(path: str | None) -> dict[str, Any]:
    cfg = json.loads(json.dumps(DEFAULTS))  # deep copy
    if path and os.path.isfile(path):
        with open(path, "r") as f:
            user = json.load(f)
        _deep_merge(cfg, user)
    return cfg


def _deep_merge(base: dict, extra: dict) -> None:
    for k, v in extra.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
