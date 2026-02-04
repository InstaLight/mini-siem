# uses schema to prevent against malicioius data
REQUIRED_AGENT_FIELDS = {"id", "hostname", "os", "ip"}
REQUIRED_EVENT_FIELDS = {"id", "timestamp", "source", "type", "severity"}


def validate_event(event: dict) -> bool:
    try:
        if "agent" not in event or "event" not in event or "data" not in event:
            return False

        if not REQUIRED_AGENT_FIELDS.issubset(event["agent"].keys()):
            return False

        if not REQUIRED_EVENT_FIELDS.issubset(event["event"].keys()):
            return False

        return True
    except Exception:
        return False
