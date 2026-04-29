"""Safe response-action execution for MVP remediation workflows."""
from __future__ import annotations

from datetime import datetime, timezone
import subprocess
import uuid

ALLOWED_ACTIONS = {"terminate_process", "isolate_host"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def execute_action(
    *,
    action_type: str,
    target_ids: list[str],
    requested_by: str,
    dry_run: bool = True,
) -> dict:
    """Execute a guarded action and return an auditable result record."""
    if action_type not in ALLOWED_ACTIONS:
        raise ValueError(f"Unsupported action_type: {action_type}")

    action = {
        "action_id": str(uuid.uuid4()),
        "action_type": action_type,
        "requested_by": requested_by or "dashboard",
        "target_ids": target_ids,
        "dry_run": dry_run,
        "status": "completed",
        "requested_at": _utc_now(),
        "completed_at": _utc_now(),
        "details": {},
    }

    if dry_run:
        action["details"] = {"result": f"Dry run: {action_type} not executed"}
        return action

    if action_type == "isolate_host":
        action["details"] = {"result": "Placeholder: host isolation agent integration pending"}
        return action

    # terminate_process: local host MVP path only
    pids = [pid for pid in target_ids if str(pid).isdigit()]
    failed: list[dict] = []
    for pid in pids:
        cmd = ["kill", "-9", str(pid)]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            failed.append({"pid": pid, "error": proc.stderr.strip()})

    action["status"] = "completed" if not failed else "partial_failure"
    action["details"] = {"attempted_pids": pids, "failed": failed}
    action["completed_at"] = _utc_now()
    return action
