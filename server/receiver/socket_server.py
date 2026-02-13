import socket
import json

from shared.schema import validate_event
from server.storage.events import store_event
from server.detection.rules import detect_ssh_bruteforce
from server.detection.rules import detect_privilege_escalation

HOST = "0.0.0.0"   # Listen on all interfaces
PORT = 9001       # Arbitrary non-privileged port
BUFFER_SIZE = 4096


def start_server():
    print(f"[+] Starting SIEM socket server on {HOST}:{PORT}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()

        print("[+] Server is listening for connections...")

        while True:
            conn, addr = server_socket.accept()
            print(f"[+] Connection received from {addr}")

            with conn:
                data = b""

                while True:
                    chunk = conn.recv(BUFFER_SIZE)
                    if not chunk:
                        break
                    data += chunk
                
                try:
                    event = json.loads(data.decode("utf-8"))
                    
                    if not validate_event(event):
                            print("[!] Invalid event, dropping")
                            return
                    store_event(event)
                    alert = detect_ssh_bruteforce(event)
                    if alert:
                        print("[ALERT DETECTED]")
                        print(alert)
                    escalation_alert = detect_privilege_escalation(event)
                    if escalation_alert:
                        print("[!!! PRIVILEGE ESCALATION ALERT !!!]")
                        print(escalation_alert)
                    print(f"[+] Event accepted from agent {event['agent']['id']}")
                except json.JSONDecodeError as e:
                    print(f"[!] Failed to decode JSON: {e}")


if __name__ == "__main__":
    start_server()
