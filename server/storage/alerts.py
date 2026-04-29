"""Alert storage - persists to alerts.json with thread-safe append."""
import uuid

from server.storage.file_io import (
    append_to_json_list,
    clear_json_list,
    ALERTS_FILE,
    alerts_lock,
    load_json_list,
    write_json_list,
)


def clear_alerts() -> bool:
    """Clear all alerts (for demo purposes). Returns True on success."""
    return clear_json_list(ALERTS_FILE, alerts_lock)


def store_alert(alert: dict) -> bool:
    """Persist alert to alerts.json. Returns True on success."""
    alert.setdefault("alert_id", str(uuid.uuid4()))
    return append_to_json_list(ALERTS_FILE, alert, alerts_lock)


def clear_alerts_by_ids(alert_ids: list[str]) -> int:
    """Delete alerts that match given alert IDs."""
    ids = set(alert_ids)
    if not ids:
        return 0

    alerts = load_json_list(ALERTS_FILE)
    normalized = []
    removed = 0
    for idx, alert in enumerate(alerts):
        if not alert.get("alert_id"):
            base = f"{alert.get('timestamp', '')}:{alert.get('alert_type', '')}:{idx}"
            alert["alert_id"] = str(uuid.uuid5(uuid.NAMESPACE_DNS, base))
        if alert["alert_id"] in ids:
            removed += 1
            continue
        normalized.append(alert)
    if removed:
        write_json_list(ALERTS_FILE, alerts_lock, normalized)
    return removed
