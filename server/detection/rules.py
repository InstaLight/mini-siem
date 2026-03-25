"""
Legacy entry point: re-exports single detectors and the registry.
Prefer importing from ``server.detection`` or ``server.detection.registry``.
"""
from server.detection.registry import run_detectors, ALL_DETECTORS
from server.detection.ssh_bruteforce import detect_ssh_bruteforce
from server.detection.failed_password import detect_failed_password
from server.detection.privilege_escalation import detect_privilege_escalation

__all__ = [
    "run_detectors",
    "ALL_DETECTORS",
    "detect_ssh_bruteforce",
    "detect_failed_password",
    "detect_privilege_escalation",
]
