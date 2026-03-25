"""
Linux /var/log/auth.log collector — normalizes lines into shared SIEM envelope.
"""
import re
import time

from shared.event_builder import make_event

AUTH_LOG_PATH = "/var/log/auth.log"

FAILED_SSH_REGEX = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

# Successful SSH (for new rules: suspicious time, new IP per user)
ACCEPTED_SSH_REGEX = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

# Traditional sudo line (Debian/Ubuntu): "sudo: user : 1 incorrect password attempt ; TTY=..."
# Also allow plural / multiple attempts and dotted usernames.
SUDO_BAD_PASSWORD_REGEX = re.compile(
    r"sudo:.*?(?P<user>[\w.-]+)\s*:\s+\d+\s+incorrect password attempts?\b",
    re.I,
)

# Same message without "user :" prefix on some versions: "sudo: 2 incorrect password attempts"
SUDO_BAD_PASSWORD_NO_USER = re.compile(
    r"sudo:\s+(?P<count>\d+)\s+incorrect password attempts?\b",
    re.I,
)

# Very common on modern Ubuntu/Debian (rsyslog/journal forwarded to auth.log):
# pam_unix(sudo:auth): authentication failure; ... user=insta
PAM_SUDO_AUTH_FAILURE = re.compile(
    r"pam_unix\(sudo:auth\):\s*authentication failure[^\n]*\buser=(?P<user>\S+)",
    re.I,
)

SUDO_REGEX = re.compile(
    r"sudo:\s+(?P<user>[\w.-]+)\s*:\s+.*COMMAND=(?P<command>.+)"
)


def follow(file):
    """Yield new lines as they appear (tail -f style)."""
    file.seek(0, 2)
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.5)
            continue
        yield line


def parse_auth_log(agent_info: dict):
    with open(AUTH_LOG_PATH, "r") as f:
        for line in follow(f):
            line = line.rstrip("\n")

            m = FAILED_SSH_REGEX.search(line)
            if m:
                yield make_event(
                    agent=agent_info.copy(),
                    event_type="authentication_failure",
                    severity="medium",
                    data={
                        "user": m.group("user"),
                        "src_ip": m.group("ip"),
                        "service": "ssh",
                        "message": line.strip(),
                    },
                    raw=line,
                    source="linux_auth_log",
                )
                continue

            m = ACCEPTED_SSH_REGEX.search(line)
            if m:
                yield make_event(
                    agent=agent_info.copy(),
                    event_type="successful_login",
                    severity="low",
                    data={
                        "user": m.group("user"),
                        "src_ip": m.group("ip"),
                        "service": "ssh",
                        "message": line.strip(),
                    },
                    raw=line,
                    source="linux_auth_log",
                )
                continue

            m = SUDO_BAD_PASSWORD_REGEX.search(line)
            if m:
                yield make_event(
                    agent=agent_info.copy(),
                    event_type="incorrect_password",
                    severity="medium",
                    data={
                        "user": m.group("user"),
                        "service": "sudo",
                        "message": line.strip(),
                    },
                    raw=line,
                    source="linux_auth_log",
                )
                continue

            m = SUDO_BAD_PASSWORD_NO_USER.search(line)
            if m:
                yield make_event(
                    agent=agent_info.copy(),
                    event_type="incorrect_password",
                    severity="medium",
                    data={
                        "user": "",
                        "service": "sudo",
                        "message": line.strip(),
                    },
                    raw=line,
                    source="linux_auth_log",
                )
                continue

            m = PAM_SUDO_AUTH_FAILURE.search(line)
            if m:
                user = m.group("user").strip()
                if user.endswith(";"):
                    user = user[:-1]
                yield make_event(
                    agent=agent_info.copy(),
                    event_type="incorrect_password",
                    severity="medium",
                    data={
                        "user": user,
                        "service": "sudo",
                        "message": line.strip(),
                    },
                    raw=line,
                    source="linux_auth_log",
                )
                continue

            m = SUDO_REGEX.search(line)
            if m:
                yield make_event(
                    agent=agent_info.copy(),
                    event_type="privilege_escalation",
                    severity="medium",
                    data={
                        "user": m.group("user"),
                        "command": m.group("command").strip(),
                        "service": "sudo",
                        "message": line.strip(),
                    },
                    raw=line,
                    source="linux_auth_log",
                )
