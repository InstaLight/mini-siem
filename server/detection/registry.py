"""
Detection registry: add a new rule by implementing `detect_*` in a module
and appending the function to ALL_DETECTORS below.
"""
from typing import Callable, Iterator

from server.detection import ssh_bruteforce
from server.detection import failed_password
from server.detection import privilege_escalation
from server.detection import sudo_abuse
from server.detection import suspicious_login_time
from server.detection import new_ip_for_user
from server.detection import distributed_bruteforce

Detector = Callable[[dict], dict | None]

# Low-noise per-event rules first; correlation / stateful rules after
ALL_DETECTORS: list[Detector] = [
    failed_password.detect_failed_password,
    ssh_bruteforce.detect_ssh_bruteforce,
    distributed_bruteforce.detect_distributed_bruteforce,
    privilege_escalation.detect_privilege_escalation,
    sudo_abuse.detect_sudo_abuse,
    suspicious_login_time.detect_suspicious_login_time,
    new_ip_for_user.detect_new_ip_for_user,
]


def run_detectors(event: dict) -> Iterator[dict]:
    """Yield zero or more alerts for one normalized event."""
    for detector in ALL_DETECTORS:
        try:
            alert = detector(event)
            if alert:
                yield alert
        except Exception as ex:
            import logging

            logging.getLogger(__name__).exception("Detector %s failed: %s", detector.__name__, ex)
            continue
