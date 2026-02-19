import socket
import json
import time

from agent.collector.linux_auth import parse_auth_log

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9001


def connect_to_server():
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((SERVER_HOST, SERVER_PORT))
            print(f"[+] Connected to server at {SERVER_HOST}:{SERVER_PORT}")
            return sock
        except Exception as e:
            print(f"[!] Connection failed: {e}")
            print("[*] Retrying in 5 seconds...")
            time.sleep(5)


def send_event(sock, event):
    try:
        message = json.dumps(event) + "\n"   # newline is CRITICAL
        sock.sendall(message.encode())
        print("[DEBUG] Event sent to server")
    except Exception as e:
        print(f"[!] Failed to send event: {e}")
        raise


def main():
    agent_info = {
        "id": "linux-agent-01",
        "hostname": socket.gethostname(),
        "os": "linux"
    }

    while True:
        sock = connect_to_server()

        try:
            for event in parse_auth_log(agent_info):
                print("[DEBUG] Sending event:", event["event"]["type"])
                send_event(sock, event)

        except Exception as e:
            print(f"[!] Error in event loop: {e}")
            print("[*] Reconnecting...")
            sock.close()
            time.sleep(2)


if __name__ == "__main__":
    main()
