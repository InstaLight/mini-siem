import socket
import json
import uuid
from datetime import datetime

SERVER_HOST = "127.0.0.1"  # change later if server is remote
SERVER_PORT = 9001


def send_event(event):
    payload = json.dumps(event).encode("utf-8")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((SERVER_HOST, SERVER_PORT))
        sock.sendall(payload)

if __name__ == "__main__":
    send_test_event()
