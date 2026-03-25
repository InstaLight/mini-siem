"""
Windows Security log collector (Event ID 4625 failed, 4624 success).

Requires: ``pip install pywin32``. Run the agent **as Administrator** so the
Security log can be read.

Uses sequential backward reads from the log tail and ``RecordNumber`` so new
events are not replayed forever.
"""
from __future__ import annotations

import re
import sys
import time
from datetime import datetime, timezone

from shared.event_builder import make_event

try:
    import win32evtlog
    import win32evtlogutil
    import win32con

    _HAS_WIN32 = True
except ImportError:
    _HAS_WIN32 = False

_USER_RE = re.compile(r"TargetUserName[>\s]+(?:<[^>]+>)?\s*([^\s<]+)", re.I)
_IP_RE = re.compile(r"IpAddress[>\s]+(?:<[^>]+>)?\s*([^\s<]+)", re.I)


def parse_auth_log(agent_info: dict):
    agent_info = agent_info.copy()
    if not _HAS_WIN32:
        print(
            "[Windows] Install pywin32: pip install pywin32",
            file=sys.stderr,
        )
        return

    server = "localhost"
    last_record = 0

    while True:
        hand = win32evtlog.OpenEventLog(server, "Security")
        if not hand:
            print("[Windows] OpenEventLog failed — run as Administrator?", file=sys.stderr)
            time.sleep(10)
            continue

        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        new_batch: list = []

        try:
            while True:
                try:
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                except OSError:
                    break
                if not events:
                    break
                stop = False
                for ev in events:
                    if getattr(ev, "RecordNumber", 0) <= last_record:
                        stop = True
                        break
                    new_batch.append(ev)
                if stop:
                    break
        finally:
            win32evtlog.CloseEventLog(hand)

        if new_batch:
            mx = max(getattr(ev, "RecordNumber", 0) for ev in new_batch)
            if last_record == 0:
                # Skip existing backlog on first connect; only forward new events after this.
                last_record = mx
            else:
                last_record = mx
                for ev in reversed(new_batch):
                    eid = ev.EventID & 0xFFFF
                    if eid in (4624, 4625):
                        yield from _event_to_records(agent_info, ev, eid)

        time.sleep(2)


def _event_to_records(agent_info: dict, ev, eid: int):
    try:
        raw_strings = win32evtlogutil.SafeFormatMessage(ev, "Security")
    except Exception:
        raw_strings = ""

    if isinstance(raw_strings, str):
        blob = raw_strings.replace("\x00", " ")
    else:
        blob = " ".join(str(s) for s in (raw_strings or []))

    user_m = _USER_RE.search(blob)
    ip_m = _IP_RE.search(blob)
    user = user_m.group(1) if user_m else ""
    src_ip = ip_m.group(1) if ip_m else ""
    if src_ip in ("-", ""):
        src_ip = ""

    ts = getattr(ev, "TimeGenerated", None)
    if ts is not None:
        if not hasattr(ts, "replace"):
            ts_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        else:
            ts_utc = ts.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    else:
        ts_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    if eid == 4625:
        evt = make_event(
            agent=agent_info,
            event_type="authentication_failure",
            severity="medium",
            data={
                "user": user,
                "src_ip": src_ip,
                "service": "winlogon",
                "message": (blob[:500] if blob else str(eid)),
            },
            raw=(blob[:2000] if blob else f"EventID={eid}"),
            source="windows_security_log",
        )
        evt["event"]["timestamp"] = ts_utc
        yield evt

    elif eid == 4624:
        evt = make_event(
            agent=agent_info,
            event_type="successful_login",
            severity="low",
            data={
                "user": user,
                "src_ip": src_ip,
                "service": "winlogon",
                "message": (blob[:500] if blob else str(eid)),
            },
            raw=(blob[:2000] if blob else f"EventID={eid}"),
            source="windows_security_log",
        )
        evt["event"]["timestamp"] = ts_utc
        yield evt
