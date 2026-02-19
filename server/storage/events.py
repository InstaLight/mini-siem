"""Event storage - persists to events.json with thread-safe append."""
from server.storage.file_io import append_to_json_list, EVENTS_FILE, events_lock


def store_event(event: dict) -> bool:
    """Persist event to events.json. Returns True on success."""
    return append_to_json_list(EVENTS_FILE, event, events_lock)


def get_events() -> list:
    """Return in-memory events (legacy). Prefer reading from file via load_json_list."""
    from server.storage.file_io import load_json_list
    return load_json_list(EVENTS_FILE)
