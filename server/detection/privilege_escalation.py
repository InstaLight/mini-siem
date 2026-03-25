"""Sudo / privilege escalation lines from collectors."""


def detect_privilege_escalation(event: dict):
    if event["event"]["type"] != "privilege_escalation":
        return None

    d = event["data"]
    return {
        "alert_type": "privilege_escalation",
        "severity": "medium",
        "username": d.get("user"),
        "client_id": event["agent"].get("id"),
        "command": d.get("command"),
        "timestamp": event["event"]["timestamp"],
    }
