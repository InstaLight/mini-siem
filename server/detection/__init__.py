"""Pluggable detection rules; see registry."""

from server.detection.registry import ALL_DETECTORS, run_detectors

__all__ = ["ALL_DETECTORS", "run_detectors"]
