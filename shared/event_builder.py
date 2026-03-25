"""
Normalized SIEM event envelope (Linux, macOS, Windows).

All collectors should produce this shape so the server and detection rules
stay platform-agnostic:

{
  "agent": {"id", "hostname", "os", "ip", ...},
  "event": {"id", "timestamp", "source", "type", "severity"},
  "data": {"user", "src_ip", "service", "message", ... optional},
  "raw": "original log line or summary"
}

TLS can wrap the same JSON payloads later without changing this schema.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Mapping

# Canonical keys in `data` (extend with platform-specific fields as needed)
DATA_KEYS_USER = "user"
DATA_KEYS_SRC_IP = "src_ip"
DATA_KEYS_SERVICE = "service"
DATA_KEYS_MESSAGE = "message"
DATA_KEYS_COMMAND = "command"


def utc_timestamp() -> str:
    """ISO-8601 UTC with Z suffix (consistent across agents)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def ensure_data_shape(data: dict[str, Any]) -> dict[str, Any]:
    """Ensure optional canonical fields exist (empty string if unknown)."""
    out = dict(data)
    out.setdefault(DATA_KEYS_USER, "")
    out.setdefault(DATA_KEYS_SRC_IP, "")
    out.setdefault(DATA_KEYS_SERVICE, "")
    out.setdefault(DATA_KEYS_MESSAGE, "")
    return out


def make_event(
    *,
    agent: Mapping[str, Any],
    event_type: str,
    severity: str,
    data: dict[str, Any],
    raw: str,
    source: str = "auth",
) -> dict[str, Any]:
    """
    Build one validated-shaped event dict.
    `data` may omit user/src_ip/service/message; they are filled with "".
    """
    return {
        "agent": dict(agent),
        "event": {
            "id": str(uuid.uuid4()),
            "timestamp": utc_timestamp(),
            "source": source,
            "type": event_type,
            "severity": severity,
        },
        "data": ensure_data_shape(data),
        "raw": raw.strip() if raw else "",
    }
