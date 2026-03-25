"""
Many sudo invocations in a short window for the same user (privilege abuse).
Stateful: tracks privilege_escalation events per user across all agents.
"""
from collections import defaultdict, deque
from datetime import timedelta

from server.detection.common import parse_timestamp

SUDO_EVENTS = defaultdict(deque)  # username -> deque[timestamps]
THRESHOLD = 6
TIME_WINDOW = timedelta(minutes=2)


def detect_sudo_abuse(event: dict):
    if event["event"]["type"] != "privilege_escalation":
        return None

    user = event["data"].get("user") or ""
    if not user:
        return None

    ts = parse_timestamp(event["event"]["timestamp"])
    q = SUDO_EVENTS[user]
    q.append(ts)
    while q and q[0] < ts - TIME_WINDOW:
        q.popleft()

    # Fire once when crossing the threshold (avoids spam on every sudo in window)
    if len(q) == THRESHOLD:
        return {
            "alert_type": "sudo_abuse",
            "severity": "high",
            "timestamp": event["event"]["timestamp"],
            "client_id": event["agent"].get("id"),
            "username": user,
            "sudo_count": len(q),
            "time_window_seconds": int(TIME_WINDOW.total_seconds()),
        }

    return None
