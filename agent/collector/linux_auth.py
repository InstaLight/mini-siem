import time
import re
from datetime import datetime
import uuid

AUTH_LOG_PATH = "/var/log/auth.log"

# ---- FAILED SSH LOGIN REGEX ----
FAILED_SSH_REGEX = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

# ---- SUDO INCORRECT PASSWORD REGEX ----
# Matches: sudo:    user : 1 incorrect password attempt ; TTY=...
SUDO_BAD_PASSWORD_REGEX = re.compile(
    r"sudo:.*?(?P<user>\w+)\s*:\s+1 incorrect password attempt"
)

# ---- SUDO PRIVILEGE ESCALATION REGEX ----
# Matches lines like:
# sudo:    insta : TTY=pts/4 ; PWD=/home/insta ; USER=root ; COMMAND=/usr/bin/whoami
SUDO_REGEX = re.compile(
    r"sudo:\s+(?P<user>\w+)\s*:\s+.*COMMAND=(?P<command>.+)"
)


def follow(file):
    """Generator that yields new lines as they are written (like tail -f)."""
    file.seek(0, 2)  # Go to end of file
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.5)
            continue
        yield line


def parse_auth_log(agent_info):
    with open(AUTH_LOG_PATH, "r") as f:
        for line in follow(f):

            # -------------------------------
            # 1️⃣ Failed SSH Login Detection
            # -------------------------------
            ssh_match = FAILED_SSH_REGEX.search(line)
            if ssh_match:
                print("[DEBUG] SSH FAILURE MATCH FOUND")

                yield {
                    "agent": agent_info,
                    "event": {
                        "id": str(uuid.uuid4()),
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "source": "auth_log",
                        "type": "authentication_failure",
                        "severity": "medium",
                    },
                    "data": {
                        "user": ssh_match.group("user"),
                        "src_ip": ssh_match.group("ip"),
                        "service": "ssh",
                        "message": line.strip()
                    },
                    "raw": line.strip()
                }

            # -------------------------------
            # 2️⃣ Sudo Incorrect Password Detection
            # -------------------------------
            sudo_bad_match = SUDO_BAD_PASSWORD_REGEX.search(line)
            if sudo_bad_match:
                print("[DEBUG] SUDO INCORRECT PASSWORD MATCH FOUND")
                yield {
                    "agent": agent_info,
                    "event": {
                        "id": str(uuid.uuid4()),
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "source": "auth_log",
                        "type": "incorrect_password",
                        "severity": "medium",
                    },
                    "data": {
                        "user": sudo_bad_match.group("user"),
                        "service": "sudo",
                        "message": line.strip()
                    },
                    "raw": line.strip()
                }
                continue  # Don't also match as privilege escalation

            # -------------------------------
            # 3️⃣ Privilege Escalation Detection
            # -------------------------------
            sudo_match = SUDO_REGEX.search(line)
            if sudo_match:
                print("[DEBUG] SUDO MATCH FOUND")

                yield {
                    "agent": agent_info,
                    "event": {
                        "id": str(uuid.uuid4()),
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "source": "auth_log",
                        "type": "privilege_escalation",
                        "severity": "medium",
                    },
                    "data": {
                        "user": sudo_match.group("user"),
                        "command": sudo_match.group("command").strip(),
                        "service": "sudo",
                        "message": line.strip()
                    },
                    "raw": line.strip()
                }
