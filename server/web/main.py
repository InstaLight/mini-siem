from fastapi import FastAPI
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi import Request

from server.storage.file_io import load_json_list, EVENTS_FILE, ALERTS_FILE
from server.storage.alerts import clear_alerts

app = FastAPI()

templates = Jinja2Templates(directory="server/web/templates")


@app.post("/alerts/clear")
def clear_alerts_endpoint():
    """Clear all alerts (demo purposes)."""
    clear_alerts()
    return RedirectResponse(url="/", status_code=303)


@app.get("/events")
def get_events():
    return load_json_list(EVENTS_FILE)


@app.get("/alerts")
def get_alerts():
    return load_json_list(ALERTS_FILE)


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    alerts = load_json_list(ALERTS_FILE)
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "alerts": alerts}
    )
