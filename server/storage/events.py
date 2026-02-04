EVENT_STORE = []


def store_event(event: dict):
    EVENT_STORE.append(event)


def get_events():
    return EVENT_STORE
