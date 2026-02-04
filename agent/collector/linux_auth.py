import time
import re
from datetime import datetime
import uuid

AUTH_LOG_PATH = "/var/log/auth.log"

FAILED_SSH_REGEX = re.compile(
    r"Failed password for (inavlid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)


def follow(file):
    """Generator that yields new lines as they are written"""
    file.seek(0, 2)
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.5)
            continue
        yield line


def parse_auth_log(agent_info):
    with open(AUTH_LOG_PATH, "r") as f:
        for line in follow(f):
            match = FAILED_SSH_REGEX.search(line)
            if match:
                print("[DEBUG] MATCH FOUND")
                yield {
                    "agent": agent_info,
                    "event": {
                        "id": str(uuid.uuid4()),
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "source": "auth_log",
                        "type": "authentication_failure",
                        "severity": "medium"
                    },
                    "data": {
                        "user": match.group("user"),
                        "src_ip": match.group("ip"),
                        "service": "ssh",
                        "message": line.strip()
                    },
                    "raw": line.strip()
                }
