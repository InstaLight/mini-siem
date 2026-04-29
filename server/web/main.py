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


SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def _selected_severities(request: Request) -> list[str]:
    requested = [s.lower() for s in request.query_params.getlist("severity")]
    normalized = [s for s in requested if s in SEVERITY_ORDER]
    return sorted(set(normalized), key=lambda s: SEVERITY_ORDER[s])


def _issues_view(request: Request) -> str:
    view = (request.query_params.get("view") or "warnings").lower()
    return view if view in {"warnings", "activity"} else "warnings"


def _admin_view(request: Request) -> str:
    view = (request.query_params.get("view") or "warnings").lower()
    return view if view in {"warnings", "activity"} else "warnings"


def _filter_alerts_and_events(
    alerts: list[dict[str, Any]],
    events: list[dict[str, Any]],
    selected: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not selected:
        filtered_alerts = alerts
        filtered_events = events
    else:
        selected_set = set(selected)
        filtered_alerts = [a for a in alerts if str(a.get("severity", "")).lower() in selected_set]
        filtered_events = [e for e in events if str(e.get("event", {}).get("severity", "")).lower() in selected_set]

    def _alert_sort_key(alert: dict[str, Any]) -> tuple[int, str]:
        sev = str(alert.get("severity", "")).lower()
        return (SEVERITY_ORDER.get(sev, 99), str(alert.get("timestamp", "")))

    def _event_sort_key(event: dict[str, Any]) -> tuple[int, str]:
        sev = str(event.get("event", {}).get("severity", "")).lower()
        ts = str(event.get("event", {}).get("timestamp", ""))
        return (SEVERITY_ORDER.get(sev, 99), ts)

    filtered_alerts = sorted(filtered_alerts, key=_alert_sort_key)
    filtered_events = sorted(filtered_events, key=_event_sort_key)
    return filtered_alerts, filtered_events


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


@app.get("/api/actions")
def list_actions_api():
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
@app.get("/health", response_class=HTMLResponse)
def health_page(request: Request):
    alerts = _enriched_alerts()
    events = _enriched_events()
    actions = get_actions()[-20:][::-1]
    sev_counts = {"low": 0, "medium": 0, "high": 0}
    for alert in alerts:
        sev = str(alert.get("severity", "")).lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
    latest_event = max((e.get("event", {}).get("timestamp", "") for e in events), default="")
    latest_alert = max((a.get("timestamp", "") for a in alerts), default="")
    latest_activity = max(latest_event, latest_alert) if (latest_event or latest_alert) else "No recent activity"
    summary = {
        "total_activity": len(events),
        "total_warnings": len(alerts),
        "high_priority": sev_counts["high"],
        "latest_activity": latest_activity,
    }
    return templates.TemplateResponse(
        request=request,
        name="health.html",
        context={
            "request": request,
            "nav_current": "health",
            "alerts": alerts,
            "events": events,
            "actions": actions,
            "severity_counts": sev_counts,
            "summary": summary,
            "allowed_actions": sorted(ALLOWED_ACTIONS),
        },
    )


@app.get("/issues", response_class=HTMLResponse)
def issues_page(request: Request):
    alerts = _enriched_alerts()
    events = _enriched_events()
    selected = _selected_severities(request)
    current_view = _issues_view(request)
    alerts, events = _filter_alerts_and_events(alerts, events, selected)
    return templates.TemplateResponse(
        request=request,
        name="issues.html",
        context={
            "request": request,
            "nav_current": "issues",
            "issues_view": current_view,
            "alerts": alerts,
            "events": events[-25:][::-1],
            "selected_severities": selected,
        },
    )


@app.get("/actions", response_class=HTMLResponse)
def actions_page(request: Request):
    actions = get_actions()[-50:][::-1]
    return templates.TemplateResponse(
        request=request,
        name="actions.html",
        context={
            "request": request,
            "nav_current": "actions",
            "actions": actions,
        },
    )


@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request):
    alerts = _enriched_alerts()
    events = _enriched_events()
    selected = _selected_severities(request)
    current_view = _admin_view(request)
    alerts, events = _filter_alerts_and_events(alerts, events, selected)
    actions = get_actions()[-20:][::-1]
    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context={
            "request": request,
            "nav_current": "admin",
            "admin_view": current_view,
            "alerts": alerts,
            "events": events,
            "actions": actions,
            "selected_severities": selected,
            "allowed_actions": sorted(ALLOWED_ACTIONS),
        },
    )
