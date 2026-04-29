#!/usr/bin/env python3
"""Seed varied demo events by sending canonical JSON to the receiver socket."""
from __future__ import annotations

import argparse
import json
import socket
from datetime import datetime, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shared.event_builder import make_event  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Seed dummy Mini-SIEM data for demos.")
    parser.add_argument("--host", default="127.0.0.1", help="Receiver host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9001, help="Receiver TCP port (default: 9001)")
    parser.add_argument(
        "--burst-multiplier",
        type=int,
        default=1,
        help="Scale event counts for heavier demo traffic (default: 1)",
    )
    return parser.parse_args()


def _manual_timestamp(hour_utc: int) -> str:
    now = datetime.now(timezone.utc).replace(hour=hour_utc, minute=30, second=0, microsecond=0)
    return now.isoformat().replace("+00:00", "Z")


def build_demo_events(multiplier: int) -> list[dict]:
    agent = {
        "id": "demo-agent-001",
        "hostname": "demo-host",
        "os": "linux",
        "ip": "10.0.0.42",
    }
    events: list[dict] = []

    # SSH brute force from one source IP (triggers failed_password + ssh_bruteforce)
    for idx in range(6 * multiplier):
        events.append(
            make_event(
                agent=agent,
                event_type="authentication_failure",
                severity="medium",
                source="demo_seed",
                data={
                    "user": "admin",
                    "src_ip": "203.0.113.9",
                    "service": "ssh",
                    "message": f"Failed SSH login attempt #{idx + 1} for admin",
                },
                raw=f"sshd: Failed password for admin from 203.0.113.9 attempt {idx + 1}",
            )
        )

    # Distributed brute force against multiple users from one source
    for user in ("alice", "bob", "carol", "dave", "erin"):
        events.append(
            make_event(
                agent=agent,
                event_type="authentication_failure",
                severity="medium",
                source="demo_seed",
                data={
                    "user": user,
                    "src_ip": "198.51.100.55",
                    "service": "ssh",
                    "message": f"Credential spray attempt for {user}",
                },
                raw=f"sshd: Failed password for invalid user {user} from 198.51.100.55",
            )
        )

    # Successful login history + new IP (triggers new_ip_for_user) and off-hours (triggers suspicious time)
    baseline_login = make_event(
        agent=agent,
        event_type="successful_login",
        severity="low",
        source="demo_seed",
        data={
            "user": "jane",
            "src_ip": "192.0.2.44",
            "service": "ssh",
            "message": "Successful login for jane from known location",
        },
        raw="sshd: Accepted password for jane from 192.0.2.44",
    )
    events.append(baseline_login)

    off_hours_new_ip = make_event(
        agent=agent,
        event_type="successful_login",
        severity="medium",
        source="demo_seed",
        data={
            "user": "jane",
            "src_ip": "198.51.100.99",
            "service": "ssh",
            "message": "Successful login for jane from new location",
        },
        raw="sshd: Accepted password for jane from 198.51.100.99",
    )
    off_hours_new_ip["event"]["timestamp"] = _manual_timestamp(23)
    events.append(off_hours_new_ip)

    # Privilege escalation burst (triggers privilege_escalation + sudo_abuse)
    for idx in range(6 * multiplier):
        events.append(
            make_event(
                agent=agent,
                event_type="privilege_escalation",
                severity="medium",
                source="demo_seed",
                data={
                    "user": "ops-user",
                    "src_ip": "",
                    "service": "sudo",
                    "command": "/usr/bin/systemctl restart nginx",
                    "message": f"Sudo invocation #{idx + 1} by ops-user",
                },
                raw=f"sudo: ops-user executed privileged command #{idx + 1}",
            )
        )

    # Incorrect password sample event
    events.append(
        make_event(
            agent=agent,
            event_type="incorrect_password",
            severity="medium",
            source="demo_seed",
            data={
                "user": "ops-user",
                "src_ip": "",
                "service": "sudo",
                "message": "Incorrect sudo password entered",
            },
            raw="sudo: 1 incorrect password attempt",
        )
    )

    return events


def send_events(host: str, port: int, events: list[dict]) -> None:
    with socket.create_connection((host, port), timeout=10) as sock:
        for event in events:
            payload = (json.dumps(event) + "\n").encode("utf-8")
            sock.sendall(payload)


def main() -> None:
    args = parse_args()
    events = build_demo_events(max(1, args.burst_multiplier))
    send_events(args.host, args.port, events)
    print(f"Seeded {len(events)} demo events to {args.host}:{args.port}")


if __name__ == "__main__":
    main()
