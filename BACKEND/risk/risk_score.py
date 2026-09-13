import logging
from typing import Dict, List, Optional

from models.m3_schemas import (
    EnrichmentResult,
    RiskFactor,
    RiskBreakdown,
    RiskResult,
)

log = logging.getLogger("risk.risk_score")

# Weight constants
_WEIGHT_THREAT_SEVERITY = 0.25
_WEIGHT_ML_CONFIDENCE = 0.25
_WEIGHT_ASSET_CRITICALITY = 0.20
_WEIGHT_VULN_CVSS = 0.20
_WEIGHT_THREAT_INTEL = 0.10

_LEVEL_BANDS = [
    (0, 20, "Low"),
    (21, 40, "Medium"),
    (41, 60, "Moderate"),
    (61, 80, "High"),
    (81, 100, "Critical"),
]

_PRIORITY_MAP = {
    "Low": "LOW",
    "Medium": "MEDIUM",
    "Moderate": "HIGH",
    "High": "HIGH_IMMEDIATE",
    "Critical": "CRITICAL_IMMEDIATE",
}

from database.risk_weights_repository import get_active_risk_weights, DEFAULT_RISK_WEIGHTS

def _apply_weight(value: int, weight: float) -> int:
    """Return the contribution of a factor (rounded to nearest integer)."""
    return int(round(value * weight))

def _determine_level(score: int) -> str:
    for low, high, label in _LEVEL_BANDS:
        if low <= score <= high:
            return label
    return "Low" if score < 0 else "Critical"


def calculate_risk(
    enrichment: EnrichmentResult,
    ml_confidence: int,
    threat_severity: int,
    weights: Optional[Dict[str, float]] = None,
) -> RiskResult:
    """Calculate the deterministic risk score for a security event.

    Parameters
    ----------
    enrichment: EnrichmentResult
        The enrichment data for the event (asset, vulnerability, mitre, threat intel).
    ml_confidence: int
        Normalized ML confidence (0-100).
    threat_severity: int
        Normalized threat severity (0-100).
    weights: Optional[Dict[str, float]]
        Configurable weights for the 5 factors. If None, loads active weights from DB.
    """
    if weights is None:
        weights = get_active_risk_weights()

    w_threat_sev = float(weights.get("threat_severity", _WEIGHT_THREAT_SEVERITY))
    w_ml_conf = float(weights.get("ml_confidence", _WEIGHT_ML_CONFIDENCE))
    w_asset = float(weights.get("asset_criticality", _WEIGHT_ASSET_CRITICALITY))
    w_vuln = float(weights.get("vulnerability_cvss", _WEIGHT_VULN_CVSS))
    w_intel = float(weights.get("threat_intelligence", _WEIGHT_THREAT_INTEL))

    # Normalized values, falling back to 0 when not found or None
    asset_val = (enrichment.asset.criticality_norm if (enrichment.asset and enrichment.asset.found) else 0) or 0
    vuln_val = (enrichment.vulnerability.cvss_norm if (enrichment.vulnerability and enrichment.vulnerability.found) else 0) or 0
    intel_val = (enrichment.threat_intel.threat_score if (enrichment.threat_intel and enrichment.threat_intel.found) else 0) or 0

    # Unrounded weighted contributions
    threat_sev_raw = threat_severity * w_threat_sev
    ml_conf_raw = ml_confidence * w_ml_conf
    asset_raw = asset_val * w_asset
    vuln_raw = vuln_val * w_vuln
    intel_raw = intel_val * w_intel

    # Base formula: Risk Score = round(weighted sum), clamped 0-100
    weighted_total = threat_sev_raw + ml_conf_raw + asset_raw + vuln_raw + intel_raw
    total_score = max(0, min(100, int(round(weighted_total))))

    factors: List[RiskFactor] = [
        RiskFactor(
            name="ThreatSeverity",
            value=threat_severity,
            weight=round(w_threat_sev, 4),
            contribution=round(threat_sev_raw, 2),
            reason="User-supplied severity score",
        ),
        RiskFactor(
            name="MLConfidence",
            value=ml_confidence,
            weight=round(w_ml_conf, 4),
            contribution=round(ml_conf_raw, 2),
            reason="Model confidence from M2 prediction",
        ),
        RiskFactor(
            name="AssetCriticality",
            value=asset_val,
            weight=round(w_asset, 4),
            contribution=round(asset_raw, 2),
            reason="Criticality of the affected asset",
        ),
        RiskFactor(
            name="VulnCVSS",
            value=vuln_val,
            weight=round(w_vuln, 4),
            contribution=round(vuln_raw, 2),
            reason="CVSS score of associated CVE",
        ),
        RiskFactor(
            name="ThreatIntel",
            value=intel_val,
            weight=round(w_intel, 4),
            contribution=round(intel_raw, 2),
            reason="Threat-intel score for matching IOC",
        ),
    ]

    level = _determine_level(total_score)
    priority = _PRIORITY_MAP.get(level, "LOW")

    breakdown = RiskBreakdown(factors=factors)
    return RiskResult(score=total_score, level=level, priority=priority, breakdown=breakdown)

