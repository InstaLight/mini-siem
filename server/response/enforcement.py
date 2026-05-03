"""Blocklist + quarantine enforcement.

Provides fast membership checks for the TCP receiver hot path and
add/remove helpers for the web layer. Cached in-process with mtime
validation so repeated checks don't re-read JSON on every event.
"""
from __future__ import annotations

import os
import threading
from datetime import datetime, timezone
from typing import Any

from server.storage.file_io import (
    BLOCKLIST_FILE,
    QUARANTINE_FILE,
    blocklist_lock,
    load_json_list,
    quarantine_lock,
    write_json_list,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class _EnforcementCache:
    """mtime-validated cache of a JSON list file, keyed by one of its fields."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._mtime: float = -1.0
        self._items: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def _refresh_if_stale(self) -> None:
        try:
            current_mtime = os.path.getmtime(self._path)
        except OSError:
            current_mtime = -1.0
        if current_mtime != self._mtime:
            with self._lock:
                if current_mtime != self._mtime:
                    self._items = load_json_list(self._path)
                    self._mtime = current_mtime

    def items(self) -> list[dict[str, Any]]:
        self._refresh_if_stale()
        return list(self._items)

    def contains(self, key: str, value: str) -> bool:
        if not value:
            return False
        self._refresh_if_stale()
        return any(str(item.get(key, "")) == value for item in self._items)


_blocklist_cache = _EnforcementCache(BLOCKLIST_FILE)
_quarantine_cache = _EnforcementCache(QUARANTINE_FILE)


def is_ip_blocked(ip: str) -> bool:
    return _blocklist_cache.contains("ip", ip)


def is_agent_quarantined(agent_id: str) -> bool:
    return _quarantine_cache.contains("agent_id", agent_id)


def list_blocked_ips() -> list[dict[str, Any]]:
    return _blocklist_cache.items()


def list_quarantined_agents() -> list[dict[str, Any]]:
    return _quarantine_cache.items()


def add_ip_block(ip: str, *, reason: str = "", added_by: str = "dashboard") -> dict[str, Any]:
    ip = (ip or "").strip()
    if not ip:
        raise ValueError("Cannot block an empty IP")
    with blocklist_lock:
        items = load_json_list(BLOCKLIST_FILE)
        for existing in items:
            if str(existing.get("ip", "")) == ip:
                return existing
        record = {
            "ip": ip,
            "reason": reason,
            "added_at": _utc_now(),
            "added_by": added_by,
        }
        items.append(record)
        write_json_list(BLOCKLIST_FILE, blocklist_lock, items)
        return record


def remove_ip_block(ip: str) -> bool:
    ip = (ip or "").strip()
    if not ip:
        return False
    with blocklist_lock:
        items = load_json_list(BLOCKLIST_FILE)
        kept = [i for i in items if str(i.get("ip", "")) != ip]
        if len(kept) == len(items):
            return False
        write_json_list(BLOCKLIST_FILE, blocklist_lock, kept)
        return True


def add_quarantine(agent_id: str, *, reason: str = "", added_by: str = "dashboard") -> dict[str, Any]:
    agent_id = (agent_id or "").strip()
    if not agent_id:
        raise ValueError("Cannot quarantine an empty agent id")
    with quarantine_lock:
        items = load_json_list(QUARANTINE_FILE)
        for existing in items:
            if str(existing.get("agent_id", "")) == agent_id:
                return existing
        record = {
            "agent_id": agent_id,
            "reason": reason,
            "added_at": _utc_now(),
            "added_by": added_by,
        }
        items.append(record)
        write_json_list(QUARANTINE_FILE, quarantine_lock, items)
        return record


def remove_quarantine(agent_id: str) -> bool:
    agent_id = (agent_id or "").strip()
    if not agent_id:
        return False
    with quarantine_lock:
        items = load_json_list(QUARANTINE_FILE)
        kept = [i for i in items if str(i.get("agent_id", "")) != agent_id]
        if len(kept) == len(items):
            return False
        write_json_list(QUARANTINE_FILE, quarantine_lock, kept)
        return True


def make_quarantine_alert(event: dict[str, Any]) -> dict[str, Any]:
    """Build a high-severity alert raised when a quarantined host keeps sending events."""
    agent = event.get("agent") or {}
    data = event.get("data") or {}
    ev = event.get("event") or {}
    return {
        "alert_type": "quarantined_host_activity",
        "severity": "high",
        "timestamp": ev.get("timestamp") or _utc_now(),
        "client_id": agent.get("id", ""),
        "username": data.get("user", ""),
        "src_ip": data.get("src_ip", ""),
        "service": data.get("service", ""),
        "message": (
            f"Quarantined host '{agent.get('id', '')}' is still sending events "
            f"(type={ev.get('type', 'unknown')})."
        ),
    }
