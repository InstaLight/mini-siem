"""Per-event alert for wrong passwords (SSH, sudo, etc.)."""


def detect_failed_password(event: dict):
    if event["event"]["type"] not in ("authentication_failure", "incorrect_password"):
        return None

    d = event["data"]
    return {
        "alert_type": "failed_password",
        "severity": "low",
        "timestamp": event["event"]["timestamp"],
        "client_id": event["agent"].get("id"),
        "username": d.get("user"),
        "src_ip": d.get("src_ip"),
        "service": d.get("service", "unknown"),
        "message": (d.get("message") or "")[:200],
    }
