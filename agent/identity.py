"""Resolve agent block from config (fill hostname, OS, IP when omitted)."""
from __future__ import annotations

import socket
import sys
from typing import Any


def guess_local_ip() -> str:
    """Best-effort outbound interface address (not sent on the wire)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def platform_os_name() -> str:
    p = sys.platform
    if p.startswith("linux"):
        return "linux"
    if p == "darwin":
        return "macos"
    if p == "win32":
        return "windows"
    return p


def resolve_agent_info(cfg_agent: dict[str, Any]) -> dict[str, Any]:
    out = dict(cfg_agent)
    if not out.get("hostname"):
        out["hostname"] = socket.gethostname()
    if not out.get("os"):
        out["os"] = platform_os_name()
    if not out.get("ip"):
        out["ip"] = guess_local_ip()
    return out
