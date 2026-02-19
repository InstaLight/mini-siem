"""Alert storage - persists to alerts.json with thread-safe append."""
from server.storage.file_io import append_to_json_list, clear_json_list, ALERTS_FILE, alerts_lock


def clear_alerts() -> bool:
    """Clear all alerts (for demo purposes). Returns True on success."""
    return clear_json_list(ALERTS_FILE, alerts_lock)


def store_alert(alert: dict) -> bool:
    """Persist alert to alerts.json. Returns True on success."""
    return append_to_json_list(ALERTS_FILE, alert, alerts_lock)
