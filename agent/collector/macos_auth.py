"""
macOS authentication-style events via ``log stream`` (preferred) or system.log.

Run the agent with elevated rights if ``log stream`` requires it on your macOS version.
"""
from __future__ import annotations

import re
import subprocess
import sys

from shared.event_builder import make_event

# Compact / text lines that commonly appear for SSH and sudo
FAILED_SSH = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
ACCEPTED_SSH = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)"
)
SUDO_CMD = re.compile(
    r"sudo:\s+(?P<user>[\w.-]+)\s*:\s+.*COMMAND=(?P<command>.+)"
)
SUDO_BAD_PW = re.compile(
    r"sudo:.*?(?P<user>[\w.-]+)\s*:\s+\d+\s+incorrect password attempts?\b",
    re.I,
)
PAM_SUDO_AUTH_FAILURE = re.compile(
    r"pam_unix\(sudo:auth\):\s*authentication failure[^\n]*\buser=(?P<user>\S+)",
    re.I,
)
GENERIC_AUTH_FAILURE_USER = re.compile(
    r"(authentication failure|failed authentication|incorrect password)[^\n]*\buser(?:name)?[=:\s]+(?P<user>[\w.-]+)",
    re.I,
)
GENERIC_AUTH_FAILURE = re.compile(
    r"(authentication failure|failed authentication|incorrect password)",
    re.I,
)


def _iter_log_stream():
    """Primary path: unified logging (macOS 10.12+)."""
    cmd = [
        "log",
        "stream",
        "--style",
        "compact",
        "--predicate",
        'eventMessage CONTAINS "sudo" '
        'OR eventMessage CONTAINS "Failed password" '
        'OR eventMessage CONTAINS "Accepted " '
        'OR eventMessage CONTAINS[c] "authentication failure" '
        'OR eventMessage CONTAINS[c] "failed authentication" '
        'OR eventMessage CONTAINS[c] "incorrect password" '
        'OR eventMessage CONTAINS[c] "loginwindow"',
    ]
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        if proc.stdout is None:
            return
        for line in proc.stdout:
            yield line.rstrip("\n")
    except FileNotFoundError:
        return


def _iter_system_log(path: str = "/var/log/system.log"):
    """Fallback: follow system.log if readable (may require root)."""
    try:
        import time

        with open(path, "r", errors="replace") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                yield line.rstrip("\n")
    except OSError:
        return


def parse_auth_log(agent_info: dict):
    """
    Merge lines from ``log stream`` when available; otherwise tail system.log.
    """
    agent_info = agent_info.copy()
    gen = _iter_log_stream()
    first = True
    for line in gen:
        first = False
        for event in _line_to_events(agent_info, line):
            yield event

    if first:
        print("[macOS] log stream unavailable or produced no lines; trying /var/log/system.log", file=sys.stderr)
        for line in _iter_system_log():
            for event in _line_to_events(agent_info, line):
                yield event


def _line_to_events(agent_info: dict, line: str):
    m = FAILED_SSH.search(line)
    if m:
        yield make_event(
            agent=agent_info,
            event_type="authentication_failure",
            severity="medium",
            data={
                "user": m.group("user"),
                "src_ip": m.group("ip"),
                "service": "ssh",
                "message": line,
            },
            raw=line,
            source="macos_log",
        )
        return

    m = ACCEPTED_SSH.search(line)
    if m:
        yield make_event(
            agent=agent_info,
            event_type="successful_login",
            severity="low",
            data={
                "user": m.group("user"),
                "src_ip": m.group("ip"),
                "service": "ssh",
                "message": line,
            },
            raw=line,
            source="macos_log",
        )
        return

    m = SUDO_BAD_PW.search(line)
    if m:
        yield make_event(
            agent=agent_info,
            event_type="incorrect_password",
            severity="medium",
            data={"user": m.group("user"), "service": "sudo", "message": line},
            raw=line,
            source="macos_log",
        )
        return

    m = PAM_SUDO_AUTH_FAILURE.search(line)
    if m:
        user = m.group("user").strip().rstrip(";")
        yield make_event(
            agent=agent_info,
            event_type="incorrect_password",
            severity="medium",
            data={"user": user, "service": "sudo", "message": line},
            raw=line,
            source="macos_log",
        )
        return

    m = SUDO_CMD.search(line)
    if m:
        yield make_event(
            agent=agent_info,
            event_type="privilege_escalation",
            severity="medium",
            data={
                "user": m.group("user"),
                "command": m.group("command").strip(),
                "service": "sudo",
                "message": line,
            },
            raw=line,
            source="macos_log",
        )
        return

    m = GENERIC_AUTH_FAILURE_USER.search(line)
    if m:
        yield make_event(
            agent=agent_info,
            event_type="authentication_failure",
            severity="medium",
            data={"user": m.group("user"), "service": "login", "message": line},
            raw=line,
            source="macos_log",
        )
        return

    if GENERIC_AUTH_FAILURE.search(line):
        yield make_event(
            agent=agent_info,
            event_type="authentication_failure",
            severity="medium",
            data={"service": "login", "message": line},
            raw=line,
            source="macos_log",
        )
