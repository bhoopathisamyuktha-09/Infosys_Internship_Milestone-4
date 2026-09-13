"""
Risk scoring for Milestone 1. Deterministic, severity-banded score —
mirrors the frontend's mockRiskScore() bands so the numbers don't jump
around when this gets replaced by the real ML model's output in Milestone 2.
"""
import hashlib

SEVERITY_BANDS = {
    "Critical": (85, 97),
    "High": (68, 84),
    "Medium": (40, 67),
    "Low": (10, 39),
}


def risk_score_for(event_id: str, severity: str) -> int:
    """Deterministic pseudo-random score within the severity's band, seeded by
    event_id so the same event always gets the same score across requests."""
    lo, hi = SEVERITY_BANDS.get(severity, (10, 39))
    seed = int(hashlib.md5(str(event_id).encode()).hexdigest(), 16)
    return lo + (seed % (hi - lo + 1))
