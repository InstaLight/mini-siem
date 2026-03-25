"""Per-source-IP failed SSH threshold within a sliding window."""
from collections import defaultdict, deque
from datetime import timedelta

from server.detection.common import parse_timestamp

FAILED_ATTEMPTS = defaultdict(deque)

THRESHOLD = 5
TIME_WINDOW = timedelta(seconds=60)


def detect_ssh_bruteforce(event: dict):
    if event["event"]["type"] != "authentication_failure":
        return None

    src_ip = event["data"].get("src_ip")
    if not src_ip:
        return None
    timestamp = parse_timestamp(event["event"]["timestamp"])

    attempts = FAILED_ATTEMPTS[src_ip]
    attempts.append(timestamp)

    while attempts and attempts[0] < timestamp - TIME_WINDOW:
        attempts.popleft()

    if len(attempts) >= THRESHOLD:
        return {
            "alert_type": "ssh_bruteforce",
            "severity": "high",
            "timestamp": event["event"]["timestamp"],
            "client_id": event["agent"].get("id"),
            "src_ip": src_ip,
            "count": len(attempts),
            "time_window_seconds": int(TIME_WINDOW.total_seconds()),
            "last_seen": event["event"]["timestamp"],
        }

    return None
