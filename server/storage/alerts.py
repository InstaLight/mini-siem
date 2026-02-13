import json
import os

ALERTS_FILE = "server/storage/alerts.json"


def store_alert(alert):
    if not os.path.exists(ALERTS_FILE):
        with open(ALERTS_FILE, "w") as f:
            json.dump([], f)

    with open(ALERTS_FILE, "r") as f:
        alerts = json.load(f)

    alerts.append(alert)

    with open(ALERTS_FILE, "w") as f:
        json.dump(alerts, f, indent=2)
