"""Event storage - persists to events.json with thread-safe append."""
from server.storage.file_io import (
    append_to_json_list,
    EVENTS_FILE,
    events_lock,
    load_json_list,
    write_json_list,
)


def store_event(event: dict) -> bool:
    """Persist event to events.json. Returns True on success."""
    if "event" in event and isinstance(event["event"], dict):
        event_id = event["event"].get("id")
        if event_id:
            event["event_id"] = event_id
    return append_to_json_list(EVENTS_FILE, event, events_lock)


def get_events() -> list:
    """Return in-memory events (legacy). Prefer reading from file via load_json_list."""
    return load_json_list(EVENTS_FILE)


def clear_events_by_ids(event_ids: list[str]) -> int:
    """Delete events that match given event IDs."""
    ids = set(event_ids)
    if not ids:
        return 0
    events = load_json_list(EVENTS_FILE)
    kept = []
    removed = 0
    for idx, event in enumerate(events):
        event_id = event.get("event_id") or event.get("event", {}).get("id") or f"legacy-event-{idx}"
        event["event_id"] = event_id
        if event_id in ids:
            removed += 1
            continue
        kept.append(event)
    if removed:
        write_json_list(EVENTS_FILE, events_lock, kept)
    return removed
