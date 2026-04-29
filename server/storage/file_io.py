"""
Thread-safe JSON file operations for SIEM storage.
Ensures files are always valid JSON lists and handles empty/corrupt files.
"""
import json
import logging
import os
import threading

logger = logging.getLogger(__name__)

# Paths relative to this module's directory
_STORAGE_DIR = os.path.dirname(os.path.abspath(__file__))
EVENTS_FILE = os.path.join(_STORAGE_DIR, "events.json")
ALERTS_FILE = os.path.join(_STORAGE_DIR, "alerts.json")
ACTIONS_FILE = os.path.join(_STORAGE_DIR, "actions.json")

# Locks for thread-safe append (socket server uses multiple threads)
events_lock = threading.Lock()
alerts_lock = threading.Lock()
actions_lock = threading.Lock()


def load_json_list(path: str) -> list:
    """
    Load a JSON file as a list. Always returns a list.
    - Missing file -> []
    - Empty file -> []
    - Invalid JSON -> [] (logs warning)
    - Valid list -> returns it
    - Valid non-list (e.g. dict) -> wraps in list for safety
    """
    if not os.path.exists(path):
        return []

    try:
        with open(path, "r") as f:
            content = f.read().strip()
            if not content:
                return []
            data = json.loads(content)
            if isinstance(data, list):
                return data
            # Corrupt: file has single object instead of array
            logger.warning("JSON file %s contained non-list, wrapping: %s", path, type(data).__name__)
            return [data]
    except json.JSONDecodeError as e:
        logger.warning("Invalid JSON in %s: %s. Returning empty list.", path, e)
        return []
    except OSError as e:
        logger.error("Failed to read %s: %s", path, e)
        return []


def append_to_json_list(path: str, item: dict, lock: threading.Lock) -> bool:
    """
    Atomically append an item to a JSON list file.
    Creates file with [] if missing. Uses lock for thread safety.
    Returns True on success, False on failure.
    """
    with lock:
        try:
            items = load_json_list(path)
            items.append(item)
            _write_json_list(path, items)
            return True
        except Exception as e:
            logger.error("Failed to append to %s: %s", path, e)
            return False


def _write_json_list(path: str, items: list) -> None:
    """Write a list as JSON to path. Ensures parent dir exists."""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w") as f:
        json.dump(items, f, indent=2)


def clear_json_list(path: str, lock: threading.Lock) -> bool:
    """Atomically clear a JSON list file (write []). Returns True on success."""
    with lock:
        try:
            _write_json_list(path, [])
            return True
        except Exception as e:
            logger.error("Failed to clear %s: %s", path, e)
            return False


def remove_items_by_ids(path: str, lock: threading.Lock, ids: set[str], id_key: str) -> int:
    """
    Remove items where item[id_key] is included in ids.
    Returns count of removed items.
    """
    if not ids:
        return 0
    with lock:
        items = load_json_list(path)
        kept = [item for item in items if str(item.get(id_key, "")) not in ids]
        removed = len(items) - len(kept)
        if removed:
            _write_json_list(path, kept)
        return removed


def write_json_list(path: str, lock: threading.Lock, items: list) -> bool:
    """Replace file contents with the provided JSON list."""
    with lock:
        try:
            _write_json_list(path, items)
            return True
        except Exception as e:
            logger.error("Failed to write %s: %s", path, e)
            return False
