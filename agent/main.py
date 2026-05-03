"""
SIEM agent: tails local auth logs and ships newline-delimited JSON to the server.

Configure with ``--config path/to/config.json`` (see ``agent/config.example.json``).
TLS can wrap the same TCP stream later without changing payloads.
"""
from __future__ import annotations

import argparse
import json
import socket
import sys
import time

from agent.config import load_config
from agent.collector import stream_normalized_events
from agent.identity import resolve_agent_info
from shared.event_builder import make_event


def parse_args():
    p = argparse.ArgumentParser(description="Mini-SIEM log forwarding agent")
    p.add_argument(
        "--config",
        "-c",
        default=None,
        help="Path to agent config JSON (server_host, server_port, agent.id, ...)",
    )
    return p.parse_args()


def connect_until_ok(host: str, port: int, delay: float) -> socket.socket:
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.connect((host, port))
            print(f"[+] Connected to SIEM at {host}:{port}", file=sys.stderr)
            return sock
        except OSError as e:
            print(f"[!] Connect failed: {e} — retry in {delay}s", file=sys.stderr)
            time.sleep(delay)


def send_event(sock: socket.socket, event: dict) -> None:
    msg = (json.dumps(event, ensure_ascii=False) + "\n").encode("utf-8")
    sock.sendall(msg)


def send_heartbeat(sock: socket.socket, agent_info: dict) -> None:
    heartbeat = make_event(
        agent=agent_info,
        event_type="agent_heartbeat",
        severity="low",
        data={
            "service": "agent",
            "message": "Agent connected and heartbeat sent",
        },
        raw="agent connected",
        source="agent_runtime",
    )
    send_event(sock, heartbeat)


def main():
    args = parse_args()
    cfg = load_config(args.config)
    host = cfg["server_host"]
    port = int(cfg["server_port"])
    reconnect = float(cfg.get("reconnect_delay_seconds") or 5)

    agent_info = resolve_agent_info(cfg["agent"])

    while True:
        sock = connect_until_ok(host, port, reconnect)
        try:
            send_heartbeat(sock, agent_info)
            for event in stream_normalized_events(agent_info):
                send_event(sock, event)
                print("[+] Sent:", event.get("event", {}).get("type"), file=sys.stderr)
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            print(f"[!] Connection lost: {e}", file=sys.stderr)
        finally:
            try:
                sock.close()
            except OSError:
                pass
        print(f"[*] Reconnecting in {reconnect}s...", file=sys.stderr)
        time.sleep(reconnect)


if __name__ == "__main__":
    main()
