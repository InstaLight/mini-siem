from collections import defaultdict, deque
from datetime import datetime, timedelta

# Track failed attempts per IP
FAILED_ATTEMPTS = defaultdict(deque)

THRESHOLD = 5
TIME_WINDOW = timedelta(seconds=60)


def parse_timestamp(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", ""))


def detect_ssh_bruteforce(event: dict):
    if event["event"]["type"] != "authentication_failure":
        return None

    src_ip = event["data"].get("src_ip")
    timestamp = parse_timestamp(event["event"]["timestamp"])

    attempts = FAILED_ATTEMPTS[src_ip]
    attempts.append(timestamp)

    # Remove old timestamps
    while attempts and attempts[0] < timestamp - TIME_WINDOW:
        attempts.popleft()

    if len(attempts) >= THRESHOLD:
        return {
            "alert_type": "ssh_bruteforce",
            "severity": "high",
            "src_ip": src_ip,
            "count": len(attempts),
            "time_window_seconds": TIME_WINDOW.seconds,
            "last_seen": event["event"]["timestamp"]
        }

    return None

def detect_privilege_escalation(event: dict):
    if event["event"]["type"] != "privilege_escalation":
        return None

    return {
        "alert_type": "privilege_escalation",
        "severity": "medium",
        "username": event["data"].get("username"),
        "command": event["data"].get("command"),
        "timestamp": event["event"]["timestamp"]
    }
