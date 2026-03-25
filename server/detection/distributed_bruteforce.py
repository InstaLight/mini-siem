"""
Many failed attempts targeting different usernames from the same IP (credential spray).
"""
from collections import defaultdict, deque
from datetime import timedelta

from server.detection.common import parse_timestamp

# per src_ip: deque of (timestamp, username)
ATTEMPTS = defaultdict(deque)

USER_THRESHOLD = 4  # distinct users
TIME_WINDOW = timedelta(seconds=120)


def detect_distributed_bruteforce(event: dict):
    if event["event"]["type"] != "authentication_failure":
        return None

    src_ip = event["data"].get("src_ip")
    user = event["data"].get("user")
    if not src_ip or not user:
        return None

    ts = parse_timestamp(event["event"]["timestamp"])
    q = ATTEMPTS[src_ip]
    users_before = {u for _, u in q}
    q.append((ts, user))
    while q and q[0][0] < ts - TIME_WINDOW:
        q.popleft()
    users = {u for _, u in q}
    if len(users_before) < USER_THRESHOLD <= len(users):
        return {
            "alert_type": "distributed_bruteforce",
            "severity": "high",
            "timestamp": event["event"]["timestamp"],
            "client_id": event["agent"].get("id"),
            "src_ip": src_ip,
            "distinct_users": sorted(users),
            "attempt_count": len(q),
            "time_window_seconds": int(TIME_WINDOW.total_seconds()),
        }

    return None
