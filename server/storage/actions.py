"""Response action audit storage."""
from server.storage.file_io import ACTIONS_FILE, actions_lock, append_to_json_list, load_json_list


def store_action(action: dict) -> bool:
    """Persist a response action record."""
    return append_to_json_list(ACTIONS_FILE, action, actions_lock)


def get_actions() -> list:
    """Return response action audit records."""
    return load_json_list(ACTIONS_FILE)
