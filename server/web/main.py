from __future__ import annotations

import csv
from io import StringIO
import uuid
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from fastapi import Request
from pydantic import BaseModel, Field

from server.storage.file_io import load_json_list, EVENTS_FILE, ALERTS_FILE
from server.storage.alerts import clear_alerts, clear_alerts_by_ids
from server.storage.events import clear_events_by_ids
from server.storage.actions import get_actions, store_action
from server.response.actions import execute_action, ALLOWED_ACTIONS

app = FastAPI()

templates = Jinja2Templates(directory="server/web/templates")


class BulkClearRequest(BaseModel):
    ids: list[str] = Field(default_factory=list)


class ActionRequest(BaseModel):
    action_type: str
    target_ids: list[str] = Field(default_factory=list)
    dry_run: bool = True
    requested_by: str = "dashboard"


def _enriched_events() -> list[dict[str, Any]]:
    events = load_json_list(EVENTS_FILE)
    for idx, event in enumerate(events):
        event_id = event.get("event_id") or event.get("event", {}).get("id")
        if not event_id:
            event_id = f"legacy-event-{idx}"
        event["event_id"] = event_id
    return events


def _enriched_alerts() -> list[dict[str, Any]]:
    alerts = load_json_list(ALERTS_FILE)
    for idx, alert in enumerate(alerts):
        if not alert.get("alert_id"):
            base = f"{alert.get('timestamp', '')}:{alert.get('alert_type', '')}:{idx}"
            alert["alert_id"] = str(uuid.uuid5(uuid.NAMESPACE_DNS, base))
    return alerts


@app.post("/alerts/clear")
def clear_alerts_endpoint():
    """Clear all alerts (demo purposes)."""
    clear_alerts()
    return RedirectResponse(url="/", status_code=303)


@app.get("/events")
def get_events():
    return _enriched_events()


@app.get("/alerts")
def get_alerts():
    return _enriched_alerts()


@app.get("/actions")
def list_actions():
    return get_actions()


@app.post("/actions/execute")
def trigger_action(req: ActionRequest):
    try:
        action = execute_action(
            action_type=req.action_type,
            target_ids=req.target_ids,
            requested_by=req.requested_by,
            dry_run=req.dry_run,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    store_action(action)
    return action


@app.get("/actions/candidates")
def list_action_candidates():
    alerts = _enriched_alerts()
    events = _enriched_events()
    return {
        "allowed_actions": sorted(ALLOWED_ACTIONS),
        "alert_candidates": [
            {"id": a["alert_id"], "kind": "alert", "type": a.get("alert_type"), "severity": a.get("severity")}
            for a in alerts
        ],
        "event_candidates": [
            {
                "id": e["event_id"],
                "kind": "event",
                "type": e.get("event", {}).get("type"),
                "severity": e.get("event", {}).get("severity"),
            }
            for e in events
        ],
    }


@app.post("/alerts/clear-selected")
def clear_selected_alerts(req: BulkClearRequest):
    removed = clear_alerts_by_ids(req.ids)
    return {"removed": removed, "requested": len(req.ids)}


@app.post("/events/clear-selected")
def clear_selected_events(req: BulkClearRequest):
    removed = clear_events_by_ids(req.ids)
    return {"removed": removed, "requested": len(req.ids)}


@app.get("/export/combined.csv")
def export_combined_csv():
    alerts = _enriched_alerts()
    events = _enriched_events()
    output = StringIO()
    fieldnames = [
        "record_kind",
        "record_id",
        "timestamp",
        "severity",
        "type",
        "agent_id",
        "hostname",
        "username",
        "src_ip",
        "service",
        "message",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for event in events:
        writer.writerow(
            {
                "record_kind": "event",
                "record_id": event.get("event_id", ""),
                "timestamp": event.get("event", {}).get("timestamp", ""),
                "severity": event.get("event", {}).get("severity", ""),
                "type": event.get("event", {}).get("type", ""),
                "agent_id": event.get("agent", {}).get("id", ""),
                "hostname": event.get("agent", {}).get("hostname", ""),
                "username": event.get("data", {}).get("user", ""),
                "src_ip": event.get("data", {}).get("src_ip", ""),
                "service": event.get("data", {}).get("service", ""),
                "message": event.get("data", {}).get("message", ""),
            }
        )

    for alert in alerts:
        writer.writerow(
            {
                "record_kind": "alert",
                "record_id": alert.get("alert_id", ""),
                "timestamp": alert.get("timestamp", ""),
                "severity": alert.get("severity", ""),
                "type": alert.get("alert_type", ""),
                "agent_id": alert.get("client_id", ""),
                "hostname": "",
                "username": alert.get("username", ""),
                "src_ip": alert.get("src_ip", ""),
                "service": alert.get("service", ""),
                "message": alert.get("message", ""),
            }
        )

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=mini-siem-combined.csv"},
    )


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    alerts = _enriched_alerts()
    events = _enriched_events()
    actions = get_actions()
    sev_counts = {"low": 0, "medium": 0, "high": 0}
    for alert in alerts:
        sev = str(alert.get("severity", "")).lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "alerts": alerts,
            "events": events,
            "actions": actions[-20:][::-1],
            "severity_counts": sev_counts,
            "allowed_actions": sorted(ALLOWED_ACTIONS),
        },
    )
