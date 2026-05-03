"""Safe response-action execution for the SIEM remediation workflow.

All destructive actions default to `dry_run=True`; the web layer asks for
`dry_run=False` explicitly. Every call produces an auditable record that
lands in `actions.json` via the caller.
"""
from __future__ import annotations

from datetime import datetime, timezone
import subprocess
import uuid
from typing import Any

from server.response.enforcement import (
    add_ip_block,
    add_quarantine,
    remove_ip_block,
    remove_quarantine,
)
from server.storage.file_io import (
    ALERTS_FILE,
    EVENTS_FILE,
    load_json_list,
)

ALLOWED_ACTIONS = {
    "terminate_process",
    "isolate_host",
    "release_quarantine",
    "block_ip",
    "unblock_ip",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _lookup_record(target_id: str) -> dict[str, Any] | None:
    """Find a record by alert_id or event_id, returning a normalized view."""
    target_id = str(target_id)
    for alert in load_json_list(ALERTS_FILE):
        if str(alert.get("alert_id", "")) == target_id:
            return {
                "kind": "alert",
                "id": target_id,
                "src_ip": str(alert.get("src_ip", "")),
                "agent_id": str(alert.get("client_id", "")),
                "username": str(alert.get("username", "")),
            }
    for event in load_json_list(EVENTS_FILE):
        event_id = event.get("event_id") or event.get("event", {}).get("id")
        if str(event_id) == target_id:
            return {
                "kind": "event",
                "id": target_id,
                "src_ip": str((event.get("data") or {}).get("src_ip", "")),
                "agent_id": str((event.get("agent") or {}).get("id", "")),
                "username": str((event.get("data") or {}).get("user", "")),
            }
    return None


def _resolve_src_ips(target_ids: list[str], fallback: str) -> list[str]:
    ips: list[str] = []
    if fallback:
        ips.append(fallback.strip())
    for tid in target_ids:
        record = _lookup_record(tid)
        if record and record["src_ip"]:
            ips.append(record["src_ip"])
        elif tid and "." in tid and not tid.count("-") >= 4:
            ips.append(tid.strip())
    seen: set[str] = set()
    ordered: list[str] = []
    for ip in ips:
        if ip and ip not in seen:
            seen.add(ip)
            ordered.append(ip)
    return ordered


def _resolve_agent_ids(target_ids: list[str], fallback: str) -> list[str]:
    agents: list[str] = []
    if fallback:
        agents.append(fallback.strip())
    for tid in target_ids:
        record = _lookup_record(tid)
        if record and record["agent_id"]:
            agents.append(record["agent_id"])
        elif tid and record is None:
            agents.append(tid.strip())
    seen: set[str] = set()
    ordered: list[str] = []
    for a in agents:
        if a and a not in seen:
            seen.add(a)
            ordered.append(a)
    return ordered


def execute_action(
    *,
    action_type: str,
    target_ids: list[str],
    requested_by: str,
    dry_run: bool = True,
    reason: str = "",
    direct_value: str = "",
) -> dict[str, Any]:
    """Execute a guarded action and return an auditable result record.

    `direct_value` lets the caller pass a raw IP / agent id (e.g. from the
    Blocklist management page) without needing a target_id lookup.
    """
    if action_type not in ALLOWED_ACTIONS:
        raise ValueError(f"Unsupported action_type: {action_type}")

    action: dict[str, Any] = {
        "action_id": str(uuid.uuid4()),
        "action_type": action_type,
        "requested_by": requested_by or "dashboard",
        "target_ids": list(target_ids),
        "dry_run": bool(dry_run),
        "reason": reason,
        "status": "completed",
        "requested_at": _utc_now(),
        "completed_at": _utc_now(),
        "details": {},
    }

    if dry_run:
        action["details"] = {"result": f"Dry run: {action_type} not executed"}
        return action

    if action_type == "terminate_process":
        pids = [pid for pid in target_ids if str(pid).isdigit()]
        failed: list[dict[str, Any]] = []
        for pid in pids:
            proc = subprocess.run(
                ["kill", "-9", str(pid)], capture_output=True, text=True, check=False
            )
            if proc.returncode != 0:
                failed.append({"pid": pid, "error": proc.stderr.strip()})
        action["status"] = "completed" if not failed else "partial_failure"
        action["details"] = {"attempted_pids": pids, "failed": failed}

    elif action_type == "isolate_host":
        agents = _resolve_agent_ids(target_ids, direct_value)
        quarantined: list[dict[str, Any]] = []
        for agent_id in agents:
            record = add_quarantine(
                agent_id,
                reason=reason or f"isolated via {requested_by or 'dashboard'}",
                added_by=requested_by or "dashboard",
            )
            quarantined.append(record)
        if not quarantined:
            action["status"] = "no_op"
            action["details"] = {"result": "No agent ids resolved from targets"}
        else:
            action["details"] = {"quarantined": quarantined}

    elif action_type == "release_quarantine":
        agents = _resolve_agent_ids(target_ids, direct_value)
        removed: list[str] = []
        for agent_id in agents:
            if remove_quarantine(agent_id):
                removed.append(agent_id)
        action["status"] = "completed" if removed else "no_op"
        action["details"] = {"released": removed}

    elif action_type == "block_ip":
        ips = _resolve_src_ips(target_ids, direct_value)
        blocked: list[dict[str, Any]] = []
        for ip in ips:
            blocked.append(
                add_ip_block(
                    ip,
                    reason=reason or f"blocked via {requested_by or 'dashboard'}",
                    added_by=requested_by or "dashboard",
                )
            )
        if not blocked:
            action["status"] = "no_op"
            action["details"] = {"result": "No source IP resolved from targets"}
        else:
            action["details"] = {"blocked": blocked}

    elif action_type == "unblock_ip":
        ips = _resolve_src_ips(target_ids, direct_value)
        removed_ips: list[str] = []
        for ip in ips:
            if remove_ip_block(ip):
                removed_ips.append(ip)
        action["status"] = "completed" if removed_ips else "no_op"
        action["details"] = {"unblocked": removed_ips}

    action["completed_at"] = _utc_now()
    return action
