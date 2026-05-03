"""Mini-SIEM web dashboard (FastAPI + Jinja2).

Server-rendered pages with a JSON API that vanilla JS polls for live updates.
Every button on every page calls a real endpoint here - no placeholder flows.
"""
from __future__ import annotations

import csv
import uuid
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from server.response.actions import ALLOWED_ACTIONS, execute_action
from server.response.enforcement import (
    list_blocked_ips,
    list_quarantined_agents,
    remove_ip_block,
    remove_quarantine,
)
from server.storage.actions import get_actions, store_action
from server.storage.alerts import clear_alerts_by_ids
from server.storage.events import clear_events_by_ids
from server.storage.file_io import ALERTS_FILE, EVENTS_FILE, load_json_list


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"

app = FastAPI(title="Mini-SIEM Dashboard")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
VALID_SEVERITIES = set(SEVERITY_ORDER.keys())




class BulkIdsRequest(BaseModel):
    ids: list[str] = Field(default_factory=list)


class ActionRequest(BaseModel):
    action_type: str
    target_ids: list[str] = Field(default_factory=list)
    dry_run: bool = False
    requested_by: str = "dashboard"
    reason: str = ""
    direct_value: str = ""


class BlocklistAddRequest(BaseModel):
    ip: str
    reason: str = ""
    requested_by: str = "dashboard"


class QuarantineAddRequest(BaseModel):
    agent_id: str
    reason: str = ""
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


def _parse_iso(ts: str) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def _since_window(value: str | None) -> datetime | None:
    """Convert a relative window (e.g. `15m`, `1h`, `24h`, `7d`, `all`) to a cutoff."""
    if not value or value.lower() in {"all", ""}:
        return None
    unit = value[-1].lower()
    try:
        number = int(value[:-1])
    except ValueError:
        return None
    now = datetime.now(timezone.utc)
    if unit == "m":
        return now - timedelta(minutes=number)
    if unit == "h":
        return now - timedelta(hours=number)
    if unit == "d":
        return now - timedelta(days=number)
    return None


def _match_text(haystack_parts: list[str], needle: str) -> bool:
    if not needle:
        return True
    needle_lc = needle.lower()
    return any(needle_lc in (h or "").lower() for h in haystack_parts)


def _filter_alerts(
    alerts: list[dict[str, Any]],
    *,
    q: str = "",
    severity: list[str] | None = None,
    user: str = "",
    ip: str = "",
    type_: str = "",
    since: datetime | None = None,
) -> list[dict[str, Any]]:
    sev_set = {s.lower() for s in (severity or []) if s.lower() in VALID_SEVERITIES}
    out: list[dict[str, Any]] = []
    for alert in alerts:
        if sev_set and str(alert.get("severity", "")).lower() not in sev_set:
            continue
        if user and user.lower() not in str(alert.get("username", "")).lower():
            continue
        if ip and ip.lower() not in str(alert.get("src_ip", "")).lower():
            continue
        if type_ and type_.lower() not in str(alert.get("alert_type", "")).lower():
            continue
        if since:
            ts = _parse_iso(str(alert.get("timestamp", "")))
            if not ts or ts < since:
                continue
        if q and not _match_text(
            [
                alert.get("alert_type"),
                alert.get("username"),
                alert.get("src_ip"),
                alert.get("service"),
                alert.get("message"),
                alert.get("client_id"),
            ],
            q,
        ):
            continue
        out.append(alert)
    out.sort(
        key=lambda a: (
            SEVERITY_ORDER.get(str(a.get("severity", "")).lower(), 99),
            -_timestamp_epoch(str(a.get("timestamp", ""))),
        )
    )
    return out


def _filter_events(
    events: list[dict[str, Any]],
    *,
    q: str = "",
    severity: list[str] | None = None,
    user: str = "",
    ip: str = "",
    type_: str = "",
    since: datetime | None = None,
) -> list[dict[str, Any]]:
    sev_set = {s.lower() for s in (severity or []) if s.lower() in VALID_SEVERITIES}
    out: list[dict[str, Any]] = []
    for event in events:
        ev = event.get("event") or {}
        data = event.get("data") or {}
        agent = event.get("agent") or {}
        if sev_set and str(ev.get("severity", "")).lower() not in sev_set:
            continue
        if user and user.lower() not in str(data.get("user", "")).lower():
            continue
        if ip and ip.lower() not in str(data.get("src_ip", "")).lower():
            continue
        if type_ and type_.lower() not in str(ev.get("type", "")).lower():
            continue
        if since:
            ts = _parse_iso(str(ev.get("timestamp", "")))
            if not ts or ts < since:
                continue
        if q and not _match_text(
            [
                ev.get("type"),
                data.get("user"),
                data.get("src_ip"),
                data.get("service"),
                data.get("message"),
                agent.get("id"),
                agent.get("hostname"),
                event.get("raw"),
            ],
            q,
        ):
            continue
        out.append(event)
    out.sort(
        key=lambda e: -_timestamp_epoch(str(e.get("event", {}).get("timestamp", "")))
    )
    return out


def _timestamp_epoch(ts: str) -> float:
    parsed = _parse_iso(ts)
    return parsed.timestamp() if parsed else 0.0


def _query_filters(request: Request) -> dict[str, Any]:
    qp = request.query_params
    return {
        "q": qp.get("q", "").strip(),
        "severity": [s for s in qp.getlist("severity") if s.lower() in VALID_SEVERITIES],
        "user": qp.get("user", "").strip(),
        "ip": qp.get("ip", "").strip(),
        "type_": qp.get("type", "").strip(),
        "since": _since_window(qp.get("since", "")),
    }


def _agents_from_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aggregate connected-agent metadata from the event stream."""
    quarantined_ids = {str(q.get("agent_id", "")) for q in list_quarantined_agents()}
    per_agent: dict[str, dict[str, Any]] = {}
    for event in events:
        agent = event.get("agent") or {}
        agent_id = str(agent.get("id") or "")
        if not agent_id:
            continue
        ts = str(event.get("event", {}).get("timestamp", ""))
        existing = per_agent.get(agent_id)
        if existing is None:
            per_agent[agent_id] = {
                "agent_id": agent_id,
                "hostname": agent.get("hostname", ""),
                "os": agent.get("os", ""),
                "ip": agent.get("ip", ""),
                "event_count": 1,
                "last_seen": ts,
                "quarantined": agent_id in quarantined_ids,
            }
        else:
            existing["event_count"] += 1
            if ts > existing["last_seen"]:
                existing["last_seen"] = ts
                existing["hostname"] = agent.get("hostname", existing["hostname"])
                existing["os"] = agent.get("os", existing["os"])
                existing["ip"] = agent.get("ip", existing["ip"])
    agents = list(per_agent.values())
    agents.sort(key=lambda a: a["last_seen"], reverse=True)
    return agents


def _severity_breakdown(alerts: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0}
    for alert in alerts:
        sev = str(alert.get("severity", "")).lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def _timeseries(events: list[dict[str, Any]], window_minutes: int, bucket_minutes: int) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=window_minutes)
    bucket_td = timedelta(minutes=bucket_minutes)
    buckets: list[dict[str, Any]] = []
    cursor = window_start
    while cursor < now:
        buckets.append(
            {
                "bucket_start": cursor.isoformat().replace("+00:00", "Z"),
                "count": 0,
                "alert_count": 0,
            }
        )
        cursor += bucket_td
    for event in events:
        ts = _parse_iso(str(event.get("event", {}).get("timestamp", "")))
        if not ts:
            continue
        if ts < window_start or ts >= now:
            continue
        idx = int((ts - window_start) // bucket_td)
        if 0 <= idx < len(buckets):
            buckets[idx]["count"] += 1
    return {
        "window_minutes": window_minutes,
        "bucket_minutes": bucket_minutes,
        "buckets": buckets,
    }


def _summary_payload() -> dict[str, Any]:
    events = _enriched_events()
    alerts = _enriched_alerts()
    sev = _severity_breakdown(alerts)
    latest_event = max((e.get("event", {}).get("timestamp", "") for e in events), default="")
    latest_alert = max((a.get("timestamp", "") for a in alerts), default="")
    latest_activity = max(latest_event, latest_alert) if (latest_event or latest_alert) else ""
    agents = _agents_from_events(events)
    return {
        "total_activity": len(events),
        "total_warnings": len(alerts),
        "high_priority": sev["high"],
        "medium_priority": sev["medium"],
        "low_priority": sev["low"],
        "latest_activity": latest_activity,
        "connected_agents": len(agents),
        "blocked_ip_count": len(list_blocked_ips()),
        "quarantined_agent_count": len(list_quarantined_agents()),
    }




@app.get("/api/summary")
def api_summary():
    return _summary_payload()


@app.get("/api/alerts")
def api_alerts(request: Request):
    alerts = _enriched_alerts()
    filters = _query_filters(request)
    filtered = _filter_alerts(alerts, **filters)
    limit = _optional_int(request.query_params.get("limit"))
    if limit is not None:
        filtered = filtered[:limit]
    return {"count": len(filtered), "alerts": filtered}


@app.get("/api/alerts/{alert_id}")
def api_alert_detail(alert_id: str):
    alerts = _enriched_alerts()
    alert = next((a for a in alerts if str(a.get("alert_id")) == alert_id), None)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"alert": alert, "related_events": _related_events_for_alert(alert)}


@app.get("/api/events")
def api_events(request: Request):
    events = _enriched_events()
    filters = _query_filters(request)
    filtered = _filter_events(events, **filters)
    limit = _optional_int(request.query_params.get("limit"))
    if limit is not None:
        filtered = filtered[:limit]
    return {"count": len(filtered), "events": filtered}


@app.get("/api/events/{event_id}")
def api_event_detail(event_id: str):
    events = _enriched_events()
    event = next((e for e in events if str(e.get("event_id")) == event_id), None)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return {"event": event, "related_events": _related_events_for_event(event)}


@app.get("/api/agents")
def api_agents():
    return {"agents": _agents_from_events(_enriched_events())}


@app.get("/api/timeseries")
def api_timeseries(window: str = "60m", bucket: str = "5m"):
    window_minutes = _parse_minutes(window, default=60)
    bucket_minutes = max(1, _parse_minutes(bucket, default=5))
    return _timeseries(_enriched_events(), window_minutes, bucket_minutes)


@app.get("/api/severity-breakdown")
def api_severity_breakdown():
    return _severity_breakdown(_enriched_alerts())


@app.get("/api/blocklist")
def api_blocklist():
    return {
        "blocked_ips": list_blocked_ips(),
        "quarantined_agents": list_quarantined_agents(),
    }


@app.post("/api/blocklist")
def api_blocklist_add(req: BlocklistAddRequest):
    try:
        action = execute_action(
            action_type="block_ip",
            target_ids=[],
            requested_by=req.requested_by,
            dry_run=False,
            reason=req.reason,
            direct_value=req.ip,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    store_action(action)
    return action


@app.delete("/api/blocklist/{ip}")
def api_blocklist_remove(ip: str, requested_by: str = "dashboard", reason: str = ""):
    action = execute_action(
        action_type="unblock_ip",
        target_ids=[],
        requested_by=requested_by,
        dry_run=False,
        reason=reason,
        direct_value=ip,
    )
    store_action(action)
    return action


@app.post("/api/quarantine")
def api_quarantine_add(req: QuarantineAddRequest):
    try:
        action = execute_action(
            action_type="isolate_host",
            target_ids=[],
            requested_by=req.requested_by,
            dry_run=False,
            reason=req.reason,
            direct_value=req.agent_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    store_action(action)
    return action


@app.delete("/api/quarantine/{agent_id}")
def api_quarantine_remove(agent_id: str, requested_by: str = "dashboard", reason: str = ""):
    action = execute_action(
        action_type="release_quarantine",
        target_ids=[],
        requested_by=requested_by,
        dry_run=False,
        reason=reason,
        direct_value=agent_id,
    )
    store_action(action)
    return action


@app.get("/api/actions")
def api_actions(limit: int | None = None):
    actions = list(reversed(get_actions()))
    if limit is not None and limit > 0:
        actions = actions[:limit]
    return {"count": len(actions), "actions": actions}


@app.get("/api/actions/candidates")
def api_action_candidates():
    alerts = _enriched_alerts()
    events = _enriched_events()
    return {
        "allowed_actions": sorted(ALLOWED_ACTIONS),
        "alert_candidates": [
            {
                "id": a["alert_id"],
                "kind": "alert",
                "type": a.get("alert_type"),
                "severity": a.get("severity"),
            }
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


@app.post("/api/actions/execute")
def api_action_execute(req: ActionRequest):
    try:
        action = execute_action(
            action_type=req.action_type,
            target_ids=req.target_ids,
            requested_by=req.requested_by,
            dry_run=req.dry_run,
            reason=req.reason,
            direct_value=req.direct_value,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    store_action(action)
    return action


@app.post("/api/alerts/clear-selected")
def api_alerts_clear_selected(req: BulkIdsRequest):
    removed = clear_alerts_by_ids(req.ids)
    return {"removed": removed, "requested": len(req.ids)}


@app.post("/api/events/clear-selected")
def api_events_clear_selected(req: BulkIdsRequest):
    removed = clear_events_by_ids(req.ids)
    return {"removed": removed, "requested": len(req.ids)}




@app.get("/events")
def legacy_get_events():
    return _enriched_events()


@app.get("/alerts")
def legacy_get_alerts():
    return _enriched_alerts()


@app.post("/alerts/clear-selected")
def legacy_clear_selected_alerts(req: BulkIdsRequest):
    removed = clear_alerts_by_ids(req.ids)
    return {"removed": removed, "requested": len(req.ids)}


@app.post("/events/clear-selected")
def legacy_clear_selected_events(req: BulkIdsRequest):
    removed = clear_events_by_ids(req.ids)
    return {"removed": removed, "requested": len(req.ids)}


@app.post("/actions/execute")
def legacy_actions_execute(req: ActionRequest):
    return api_action_execute(req)


@app.get("/actions/candidates")
def legacy_action_candidates():
    return api_action_candidates()


@app.post("/alerts/clear")
def legacy_clear_alerts():
    alerts = _enriched_alerts()
    clear_alerts_by_ids([a["alert_id"] for a in alerts])
    return RedirectResponse(url="/", status_code=303)




def _stream_csv(name: str, rows: list[dict[str, Any]], fieldnames: list[str]) -> StreamingResponse:
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow({k: row.get(k, "") for k in fieldnames})
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={name}"},
    )


@app.get("/export/combined.csv")
def export_combined_csv():
    alerts = _enriched_alerts()
    events = _enriched_events()
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
    rows: list[dict[str, Any]] = []
    for event in events:
        rows.append(
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
        rows.append(
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
    return _stream_csv("mini-siem-combined.csv", rows, fieldnames)


@app.get("/export/alerts.csv")
def export_alerts_csv():
    alerts = _enriched_alerts()
    fieldnames = [
        "alert_id",
        "timestamp",
        "severity",
        "alert_type",
        "client_id",
        "username",
        "src_ip",
        "service",
        "message",
    ]
    return _stream_csv("mini-siem-warnings.csv", alerts, fieldnames)


@app.get("/export/events.csv")
def export_events_csv():
    events = _enriched_events()
    rows = []
    for event in events:
        rows.append(
            {
                "event_id": event.get("event_id", ""),
                "timestamp": event.get("event", {}).get("timestamp", ""),
                "severity": event.get("event", {}).get("severity", ""),
                "type": event.get("event", {}).get("type", ""),
                "agent_id": event.get("agent", {}).get("id", ""),
                "hostname": event.get("agent", {}).get("hostname", ""),
                "username": event.get("data", {}).get("user", ""),
                "src_ip": event.get("data", {}).get("src_ip", ""),
                "service": event.get("data", {}).get("service", ""),
                "message": event.get("data", {}).get("message", ""),
                "quarantined": bool(event.get("quarantined", False)),
            }
        )
    fieldnames = [
        "event_id",
        "timestamp",
        "severity",
        "type",
        "agent_id",
        "hostname",
        "username",
        "src_ip",
        "service",
        "message",
        "quarantined",
    ]
    return _stream_csv("mini-siem-activity.csv", rows, fieldnames)


@app.get("/export/actions.csv")
def export_actions_csv():
    actions = get_actions()
    rows = []
    for action in actions:
        rows.append(
            {
                "action_id": action.get("action_id", ""),
                "action_type": action.get("action_type", ""),
                "requested_by": action.get("requested_by", ""),
                "requested_at": action.get("requested_at", ""),
                "completed_at": action.get("completed_at", ""),
                "status": action.get("status", ""),
                "dry_run": bool(action.get("dry_run", False)),
                "target_ids": ";".join(action.get("target_ids", [])),
                "reason": action.get("reason", ""),
                "details": str(action.get("details", "")),
            }
        )
    fieldnames = [
        "action_id",
        "action_type",
        "requested_by",
        "requested_at",
        "completed_at",
        "status",
        "dry_run",
        "target_ids",
        "reason",
        "details",
    ]
    return _stream_csv("mini-siem-responses.csv", rows, fieldnames)




def _parse_minutes(value: str, *, default: int) -> int:
    if not value:
        return default
    try:
        if value.endswith("h"):
            return int(value[:-1]) * 60
        if value.endswith("m"):
            return int(value[:-1])
        if value.endswith("d"):
            return int(value[:-1]) * 24 * 60
        return int(value)
    except ValueError:
        return default


def _optional_int(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _related_events_for_alert(alert: dict[str, Any]) -> list[dict[str, Any]]:
    src_ip = str(alert.get("src_ip", ""))
    user = str(alert.get("username", ""))
    client = str(alert.get("client_id", ""))
    return _match_related_events(src_ip=src_ip, user=user, agent_id=client)


def _related_events_for_event(event: dict[str, Any]) -> list[dict[str, Any]]:
    data = event.get("data") or {}
    agent = event.get("agent") or {}
    return _match_related_events(
        src_ip=str(data.get("src_ip", "")),
        user=str(data.get("user", "")),
        agent_id=str(agent.get("id", "")),
        exclude_event_id=event.get("event_id"),
    )


def _match_related_events(
    *,
    src_ip: str = "",
    user: str = "",
    agent_id: str = "",
    exclude_event_id: str | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    events = _enriched_events()
    matched: list[dict[str, Any]] = []
    for event in events:
        if exclude_event_id and event.get("event_id") == exclude_event_id:
            continue
        data = event.get("data") or {}
        agent = event.get("agent") or {}
        hit = (
            (src_ip and str(data.get("src_ip", "")) == src_ip)
            or (user and str(data.get("user", "")) == user)
            or (agent_id and str(agent.get("id", "")) == agent_id)
        )
        if hit:
            matched.append(event)
    matched.sort(
        key=lambda e: -_timestamp_epoch(str(e.get("event", {}).get("timestamp", "")))
    )
    return matched[:limit]




def _page_context(request: Request, *, nav_current: str, **extra: Any) -> dict[str, Any]:
    ctx = {
        "request": request,
        "nav_current": nav_current,
        "summary": _summary_payload(),
        "allowed_actions": sorted(ALLOWED_ACTIONS),
    }
    ctx.update(extra)
    return ctx


@app.get("/", response_class=HTMLResponse)
def page_overview(request: Request):
    events = _enriched_events()
    alerts = _enriched_alerts()
    agents = _agents_from_events(events)
    latest_alerts = sorted(
        alerts,
        key=lambda a: -_timestamp_epoch(str(a.get("timestamp", ""))),
    )[:5]
    latest_events = sorted(
        events,
        key=lambda e: -_timestamp_epoch(str(e.get("event", {}).get("timestamp", ""))),
    )[:5]
    severity = _severity_breakdown(alerts)
    ctx = _page_context(
        request,
        nav_current="overview",
        latest_alerts=latest_alerts,
        latest_events=latest_events,
        agents=agents[:8],
        severity=severity,
    )
    return templates.TemplateResponse(request=request, name="overview.html", context=ctx)


@app.get("/warnings", response_class=HTMLResponse)
def page_warnings(request: Request):
    alerts = _enriched_alerts()
    filters = _query_filters(request)
    filtered = _filter_alerts(alerts, **filters)
    types = sorted({str(a.get("alert_type", "")) for a in alerts if a.get("alert_type")})
    ctx = _page_context(
        request,
        nav_current="warnings",
        alerts=filtered,
        total_alerts=len(alerts),
        alert_types=types,
        filters_view={
            "q": filters["q"],
            "severity": filters["severity"],
            "user": filters["user"],
            "ip": filters["ip"],
            "type": filters["type_"],
            "since": request.query_params.get("since", "all"),
        },
    )
    return templates.TemplateResponse(request=request, name="warnings_list.html", context=ctx)


@app.get("/warnings/{alert_id}", response_class=HTMLResponse)
def page_warning_detail(request: Request, alert_id: str):
    alerts = _enriched_alerts()
    alert = next((a for a in alerts if str(a.get("alert_id")) == alert_id), None)
    if not alert:
        raise HTTPException(status_code=404, detail="Warning not found")
    related = _related_events_for_alert(alert)
    ctx = _page_context(
        request,
        nav_current="warnings",
        alert=alert,
        related_events=related,
    )
    return templates.TemplateResponse(request=request, name="warning_detail.html", context=ctx)


@app.get("/activity", response_class=HTMLResponse)
def page_activity(request: Request):
    events = _enriched_events()
    filters = _query_filters(request)
    filtered = _filter_events(events, **filters)
    types = sorted(
        {str(e.get("event", {}).get("type", "")) for e in events if e.get("event", {}).get("type")}
    )
    ctx = _page_context(
        request,
        nav_current="activity",
        events=filtered,
        total_events=len(events),
        event_types=types,
        filters_view={
            "q": filters["q"],
            "severity": filters["severity"],
            "user": filters["user"],
            "ip": filters["ip"],
            "type": filters["type_"],
            "since": request.query_params.get("since", "all"),
        },
    )
    return templates.TemplateResponse(request=request, name="activity_list.html", context=ctx)


@app.get("/activity/{event_id}", response_class=HTMLResponse)
def page_activity_detail(request: Request, event_id: str):
    events = _enriched_events()
    event = next((e for e in events if str(e.get("event_id")) == event_id), None)
    if not event:
        raise HTTPException(status_code=404, detail="Activity record not found")
    related = _related_events_for_event(event)
    ctx = _page_context(
        request,
        nav_current="activity",
        event=event,
        related_events=related,
    )
    return templates.TemplateResponse(request=request, name="activity_detail.html", context=ctx)


@app.get("/agents", response_class=HTMLResponse)
def page_agents(request: Request):
    events = _enriched_events()
    agents = _agents_from_events(events)
    ctx = _page_context(request, nav_current="agents", agents=agents)
    return templates.TemplateResponse(request=request, name="agents.html", context=ctx)


@app.get("/responses", response_class=HTMLResponse)
def page_responses(request: Request):
    actions = list(reversed(get_actions()))
    status_filter = request.query_params.get("status", "").strip()
    type_filter = request.query_params.get("type", "").strip()
    if status_filter:
        actions = [a for a in actions if str(a.get("status", "")) == status_filter]
    if type_filter:
        actions = [a for a in actions if str(a.get("action_type", "")) == type_filter]
    ctx = _page_context(
        request,
        nav_current="responses",
        actions=actions,
        status_filter=status_filter,
        type_filter=type_filter,
        action_types=sorted({str(a.get("action_type", "")) for a in get_actions() if a.get("action_type")}),
        statuses=sorted({str(a.get("status", "")) for a in get_actions() if a.get("status")}),
    )
    return templates.TemplateResponse(request=request, name="responses.html", context=ctx)


@app.get("/blocklist", response_class=HTMLResponse)
def page_blocklist(request: Request):
    ctx = _page_context(
        request,
        nav_current="blocklist",
        blocked_ips=list_blocked_ips(),
        quarantined_agents=list_quarantined_agents(),
    )
    return templates.TemplateResponse(request=request, name="blocklist.html", context=ctx)




@app.get("/health")
def legacy_health():
    return RedirectResponse(url="/", status_code=307)


@app.get("/issues")
def legacy_issues(request: Request):
    view = request.query_params.get("view", "warnings")
    target = "/activity" if view == "activity" else "/warnings"
    qs = "&".join(f"severity={s}" for s in request.query_params.getlist("severity"))
    url = f"{target}?{qs}" if qs else target
    return RedirectResponse(url=url, status_code=307)


@app.get("/actions")
def legacy_actions():
    return RedirectResponse(url="/responses", status_code=307)


@app.get("/admin")
def legacy_admin():
    return RedirectResponse(url="/warnings", status_code=307)
