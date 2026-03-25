"""
First-time (for this server process) source IP for a user who already has history.
"""
# username (lowercased) -> set of src_ip seen on successful_login
USER_IPS: dict[str, set[str]] = {}


def detect_new_ip_for_user(event: dict):
    if event["event"]["type"] != "successful_login":
        return None

    user = (event["data"].get("user") or "").lower()
    src_ip = event["data"].get("src_ip") or ""
    if not user or not src_ip:
        return None

    known = USER_IPS.setdefault(user, set())

    if src_ip in known:
        return None

    is_new_for_existing_user = len(known) > 0
    known.add(src_ip)

    if not is_new_for_existing_user:
        return None

    return {
        "alert_type": "new_ip_for_user",
        "severity": "medium",
        "timestamp": event["event"]["timestamp"],
        "client_id": event["agent"].get("id"),
        "username": user,
        "src_ip": src_ip,
        "message": f"User {user} logged in from new IP {src_ip}",
    }
