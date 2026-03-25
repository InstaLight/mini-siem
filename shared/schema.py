"""
Event validation for the TCP receiver.
Keep rules small — collectors normalize into the envelope; we only check
required keys for safety. (TLS will authenticate agents later.)
"""
from typing import Any

REQUIRED_AGENT_FIELDS = {"id", "hostname", "os", "ip"}
REQUIRED_EVENT_FIELDS = {"id", "timestamp", "source", "type", "severity"}
# Best-effort canonical fields in `data` (values may be "")
REQUIRED_DATA_FIELDS = {"user", "src_ip", "service", "message"}

# Document types rules may use (not exhaustive)
EVENT_TYPES = frozenset(
    {
        "authentication_failure",
        "incorrect_password",
        "privilege_escalation",
        "successful_login",
    }
)


def validate_event(event: dict[str, Any]) -> bool:
    try:
        if "agent" not in event or "event" not in event or "data" not in event:
            return False
        if not REQUIRED_AGENT_FIELDS.issubset(event["agent"].keys()):
            return False
        if not REQUIRED_EVENT_FIELDS.issubset(event["event"].keys()):
            return False
        if "raw" not in event:
            return False
        # Normalized data: must include canonical keys (may be empty strings)
        if not REQUIRED_DATA_FIELDS.issubset(event["data"].keys()):
            return False
        return True
    except Exception:
        return False
