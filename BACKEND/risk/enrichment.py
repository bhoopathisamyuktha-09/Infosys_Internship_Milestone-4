"""
risk/enrichment.py — Milestone 3 Event Enrichment Engine
=========================================================
Milestone 3: Risk Prioritization & Security Intelligence

Enriches a raw security event with contextual data from:
  - assets (criticality, department, owner)
  - vulnerabilities (CVE, CVSS)
  - mitre_attack_mapping (MITRE technique, tactic)
  - threat_intelligence (IOC matching: source_ip first, then destination_ip)

IOC Lookup Precedence:
  1. source_ip is checked against threat_intelligence.indicator_value
  2. If no source_ip match, destination_ip is checked
  3. If both match different records, source_ip takes precedence
  4. ioc_matched_field records which IP field produced the match

Threat Intelligence Fields Mapped:
  - threat_name   ← record["threat_name"]
  - threat_actor  ← record["threat_actor"]   (NOT confidence, NOT severity)
  - confidence    ← record["confidence"]
  - severity      ← record["severity"]
  - threat_score  ← normalized from confidence/severity
"""

import logging
from typing import Optional

import database.mongo_db as mongo_module
from models.m3_schemas import (
    EnrichmentAsset,
    EnrichmentVulnerability,
    EnrichmentMitre,
    EnrichmentThreatIntel,
    EnrichmentResult,
)
from services.data_store import store

log = logging.getLogger("risk.enrichment")

# Normalization helpers
_CRITICALITY_MAP = {
    "Critical": 100,
    "High": 75,
    "Medium": 50,
    "Low": 25,
}

_THREAT_INTEL_MAP = {
    "malicious": 100,
    "critical": 100,
    "high": 80,
    "medium": 60,
    "low": 40,
    "none": 0,
}


def _normalize_criticality(value: Optional[str]) -> Optional[int]:
    if not value:
        return None
    return _CRITICALITY_MAP.get(value)


def _normalize_cvss(cvss: Optional[float]) -> Optional[int]:
    if cvss is None:
        return None
    norm = int(round(cvss * 10))
    return max(0, min(100, norm))


def _normalize_threat_intel(doc: Optional[dict]) -> Optional[int]:
    """Normalize threat intel score based on confidence then severity."""
    if not doc:
        return None
    for field in ("confidence", "severity"):
        val = doc.get(field)
        if val and isinstance(val, str):
            score = _THREAT_INTEL_MAP.get(val.lower())
            if score is not None:
                return score
    return 40  # Default score for matched IOC with unspecified category


def enrich_asset(event: dict) -> EnrichmentAsset:
    asset_name = event.get("asset_name")
    if not asset_name:
        return EnrichmentAsset(found=False)
    coll = mongo_module.mongo.get_database()["assets"]
    doc = coll.find_one({"asset_name": asset_name})
    if not doc:
        return EnrichmentAsset(found=False)
    crit = doc.get("criticality")
    return EnrichmentAsset(
        found=True,
        asset_id=doc.get("asset_id"),
        asset_name=doc.get("asset_name"),
        asset_type=doc.get("asset_type"),
        owner=doc.get("owner"),
        department=doc.get("department"),
        criticality=crit,
        criticality_norm=_normalize_criticality(crit),
    )


def enrich_vulnerability(event: dict) -> EnrichmentVulnerability:
    vuln_id = event.get("vulnerability_id")
    coll = mongo_module.mongo.get_database()["vulnerabilities"]
    doc = coll.find_one({"cve_id": vuln_id}) if vuln_id else None
    if doc:
        cvss = doc.get("cvss_score")
        return EnrichmentVulnerability(
            found=True,
            cve_id=doc.get("cve_id"),
            cvss_score=cvss,
            cvss_norm=_normalize_cvss(cvss),
        )
    # Fallback to event cvss_score if available
    event_cvss = event.get("cvss_score")
    if event_cvss is not None:
        try:
            cvss_f = float(event_cvss)
            return EnrichmentVulnerability(
                found=True,
                cve_id=vuln_id,
                cvss_score=cvss_f,
                cvss_norm=_normalize_cvss(cvss_f),
            )
        except (ValueError, TypeError):
            pass
    return EnrichmentVulnerability(found=False)


def enrich_mitre(event: dict) -> EnrichmentMitre:
    event_type = event.get("event_type")
    if not event_type:
        return EnrichmentMitre(found=False)
    mitre = store.mitre_for(event_type)
    if not mitre:
        return EnrichmentMitre(found=False)
    return EnrichmentMitre(
        found=True,
        technique_id=mitre.get("technique_id"),
        technique_name=mitre.get("technique_name"),
        tactic=mitre.get("tactic"),
    )


def enrich_threat_intel(event: dict) -> EnrichmentThreatIntel:
    """
    Look up IOC against the threat_intelligence collection.

    Precedence:
      1. source_ip is checked first.
      2. If no match, destination_ip is checked.
      3. If both match, source_ip record is used (documented precedence).
      4. ioc_matched_field records which field produced the match.

    Threat actor, threat name, confidence, and severity are mapped
    DIRECTLY from the threat_intelligence record — NOT from derived categories.
    """
    coll = mongo_module.mongo.get_database()["threat_intelligence"]

    source_ip = event.get("source_ip")
    dest_ip = event.get("destination_ip")

    doc = None
    matched_field = None

    # 1. Try source_ip first
    if source_ip and source_ip.strip() and source_ip.lower() not in ("unknown", "none", "n/a", ""):
        doc = coll.find_one({"indicator_value": source_ip})
        if doc:
            matched_field = "source_ip"

    # 2. Fall back to destination_ip if source didn't match
    if doc is None and dest_ip and dest_ip.strip() and dest_ip.lower() not in ("unknown", "none", "n/a", ""):
        doc = coll.find_one({"indicator_value": dest_ip})
        if doc:
            matched_field = "destination_ip"

    if not doc:
        return EnrichmentThreatIntel(found=False)

    threat_score = _normalize_threat_intel(doc)

    return EnrichmentThreatIntel(
        found=True,
        ioc_value=doc.get("indicator_value"),
        ioc_type=doc.get("indicator_type"),
        threat_name=doc.get("threat_name"),                  # Real campaign name
        threat_actor=doc.get("threat_actor"),                # Real threat_actor (e.g. "Unknown")
        confidence=doc.get("confidence"),                    # e.g. "High", "Critical"
        severity=doc.get("severity"),                        # e.g. "High", "Critical"
        threat_score=threat_score,
        ioc_matched_field=matched_field,
    )


def enrich_event(event: dict) -> EnrichmentResult:
    """Collect enrichment data for a security event."""
    return EnrichmentResult(
        asset=enrich_asset(event),
        vulnerability=enrich_vulnerability(event),
        mitre=enrich_mitre(event),
        threat_intel=enrich_threat_intel(event),
    )
