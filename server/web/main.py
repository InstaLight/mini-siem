from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi import Request
import os
import json

app = FastAPI()

templates = Jinja2Templates(directory="server/web/templates")

EVENTS_FILE = "server/storage/events.json"
ALERTS_FILE = "server/storage/alerts.json"


def load_json_file(path):
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        return json.load(f)


@app.get("/events")
def get_events():
    return load_json_file(EVENTS_FILE)


@app.get("/alerts")
def get_alerts():
    return load_json_file(ALERTS_FILE)


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    alerts = load_json_file(ALERTS_FILE)
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "alerts": alerts}
    )
