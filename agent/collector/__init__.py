"""Platform-specific auth log collectors — all emit normalized SIEM events."""
from __future__ import annotations

import sys
from typing import Iterator

from agent.collector import linux_auth
from agent.collector import macos_auth
from agent.collector import windows_auth


def get_collector_module():
    p = sys.platform
    if p == "darwin":
        return macos_auth
    if p == "win32":
        return windows_auth
    return linux_auth


def stream_normalized_events(agent_info: dict) -> Iterator[dict]:
    """Yield events from the right collector for this OS."""
    mod = get_collector_module()
    yield from mod.parse_auth_log(agent_info)
