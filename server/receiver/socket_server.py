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

HOST = "0.0.0.0"
PORT = 9001
BUFFER_SIZE = 4096

def handle_client(conn, addr):
    print(f"[+] Connected to agent: {addr}")

    buffer = ""

    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break

            buffer += data.decode()

            # Handle multiple JSON objects in stream
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)

                if not line.strip():
                    continue

                try:
                    event = json.loads(line)

                    # Validate schema
                    validate_event(event)

                    # Store event
                    store_event(event)

                    # Run modular detection pipeline
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
