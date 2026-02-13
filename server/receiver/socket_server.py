import socket
import threading
import json

from shared.schema import validate_event
from server.storage.events import store_event
from server.storage.alerts import store_alert
from server.detection.rules import (
    detect_ssh_bruteforce,
    detect_privilege_escalation
)

HOST = "0.0.0.0"
PORT = 9001  # Use your updated port


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

                    # Run detection rules
                    brute_alert = detect_ssh_bruteforce(event)
                    escalation_alert = detect_privilege_escalation(event)

                    # Handle brute force alert
                    if brute_alert:
                        print("\n[!!! BRUTE FORCE ALERT !!!]")
                        print(json.dumps(brute_alert, indent=2))
                        store_alert(brute_alert)

                    # Handle escalation alert
                    if escalation_alert:
                        print("\n[!!! PRIVILEGE ESCALATION ALERT !!!]")
                        print(json.dumps(escalation_alert, indent=2))
                        store_alert(escalation_alert)

                except json.JSONDecodeError:
                    print("[!] Invalid JSON received")
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
