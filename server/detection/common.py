"""Shared helpers for detection rules (timestamps, deques)."""
from datetime import datetime


def parse_timestamp(ts: str) -> datetime:
    """Parse ISO-8601 from agents (supports trailing Z)."""
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))
