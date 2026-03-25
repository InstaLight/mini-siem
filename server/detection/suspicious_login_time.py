"""
Flag successful logins outside typical business hours (UTC hour < 6 or >= 22).
Adjust hours in constants for your org.
"""
from server.detection.common import parse_timestamp

NIGHT_START_HOUR = 22  # inclusive (UTC)
NIGHT_END_HOUR = 6  # exclusive (UTC)


def _is_suspicious_hour(dt) -> bool:
    h = dt.hour
    return h >= NIGHT_START_HOUR or h < NIGHT_END_HOUR


def detect_suspicious_login_time(event: dict):
    if event["event"]["type"] != "successful_login":
        return None

    ts = parse_timestamp(event["event"]["timestamp"])
    if not _is_suspicious_hour(ts):
        return None

    d = event["data"]
    return {
        "alert_type": "suspicious_login_time",
        "severity": "medium",
        "timestamp": event["event"]["timestamp"],
        "client_id": event["agent"].get("id"),
        "username": d.get("user"),
        "src_ip": d.get("src_ip"),
        "message": f"Login at {ts.isoformat()} (UTC) outside normal hours",
    }
