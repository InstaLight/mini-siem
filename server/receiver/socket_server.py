"""
TCP newline-delimited JSON receiver. One agent connection = one thread.
Future: wrap this socket in TLS (``ssl.wrap_socket`` or asyncio TLS) without
changing the JSON message format.
"""
import json
import socket
import threading

from shared.schema import validate_event
from server.detection import run_detectors
from server.storage.alerts import store_alert
from server.storage.events import store_event
from server.response.enforcement import (
    is_agent_quarantined,
    is_ip_blocked,
    make_quarantine_alert,
)

HOST = "0.0.0.0"
PORT = 9001
BUFFER_SIZE = 4096


def _event_src_ip(event: dict) -> str:
    return str((event.get("data") or {}).get("src_ip") or "")


def _event_agent_id(event: dict) -> str:
    return str((event.get("agent") or {}).get("id") or "")


def handle_client(conn, addr):
    print(f"[+] Connected to agent: {addr}")

    buffer = ""

    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break

            buffer += data.decode()

            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)

                if not line.strip():
                    continue

                try:
                    event = json.loads(line)

                    if not validate_event(event):
                        print("[!] Event failed schema validation; dropped")
                        continue

                    src_ip = _event_src_ip(event)
                    agent_id = _event_agent_id(event)

                    if src_ip and is_ip_blocked(src_ip):
                        print(f"[BLOCK] dropping event from blocked IP {src_ip}")
                        continue

                    if agent_id and is_agent_quarantined(agent_id):
                        event["quarantined"] = True
                        store_event(event)
                        quarantine_alert = make_quarantine_alert(event)
                        print(
                            f"\n[ALERT:HIGH] quarantined_host_activity "
                            f"agent={agent_id}"
                        )
                        store_alert(quarantine_alert)
                        for alert in run_detectors(event):
                            store_alert(alert)
                        continue

                    store_event(event)

                    for alert in run_detectors(event):
                        sev = alert.get("severity", "").upper()
                        print(f"\n[ALERT:{sev}] {alert.get('alert_type')}")
                        print(json.dumps(alert, indent=2))
                        store_alert(alert)

                except json.JSONDecodeError:
                    print("[!] Invalid JSON payload received from agent")
                except Exception as e:
                    print(f"[!] Error processing event: {e}")

    finally:
        conn.close()
        print(f"[-] Disconnected from agent: {addr}")


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()

    print(f"[+] Mini-SIEM Server listening on {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.daemon = True
        thread.start()


if __name__ == "__main__":
    start_server()
