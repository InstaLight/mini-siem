from agent.collector.linux_auth import parse_auth_log
from agent.transport.socket_client import send_event

AGENT_INFO = {
    "id": "agent-01",
    "hostname": "linux-test",
    "os": "linux",
    "ip": "127.0.0.1"
}


def main():
    print("[+] Linux agent started, monitoring auth.log")

    for event in parse_auth_log(AGENT_INFO):
        send_event(event)


if __name__ == "__main__":
    main()
