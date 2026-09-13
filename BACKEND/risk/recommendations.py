"""
risk/recommendations.py — Milestone 3 Advisory Security Recommendations Engine
==============================================================================
Milestone 3: Risk Prioritization & Security Intelligence

Advisory-only recommendations mapped to detected threat types and attack chains.
Non-destructive: NEVER executes automatic blocks, isolation, or deletions.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from models.m3_schemas import (
    AttackChainResult,
    EnrichmentResult,
    Recommendation,
)

log = logging.getLogger("risk.recommendations")

_RECOMMENDATIONS_CATALOG = {
    "Brute Force": [
        Recommendation(
            action="Investigate source IP address",
            reason="Identify geographic origin and reputation of credential guessing activity",
            priority="HIGH",
        ),
        Recommendation(
            action="Review authentication logs",
            reason="Assess scope of failed login attempts across domain accounts",
            priority="HIGH",
        ),
        Recommendation(
            action="Investigate affected user account",
            reason="Check for unauthorized access or compromised credentials",
            priority="CRITICAL",
        ),
        Recommendation(
            action="Consider temporary account lock",
            reason="Advisory: Prevent automated credential-stuffing tool progression",
            priority="MEDIUM",
        ),
        Recommendation(
            action="Enable multi-factor authentication (MFA)",
            reason="Enforce additional verification layer on vulnerable accounts",
            priority="HIGH",
        ),
    ],
    "Failed Login": [
        Recommendation(
            action="Review authentication failure reasons",
            reason="Determine if failures represent brute force or user error",
            priority="MEDIUM",
        ),
        Recommendation(
            action="Inspect source IP against threat intelligence",
            reason="Check whether failure originated from known malicious infrastructure",
            priority="HIGH",
        ),
        Recommendation(
            action="Verify account lockout policies",
            reason="Ensure brute force thresholds are enforced properly",
            priority="MEDIUM",
        ),
    ],
    "Login Success": [
        Recommendation(
            action="Verify login geolocation and anomalous timing",
            reason="Confirm session matches normal user behavioral baseline",
            priority="MEDIUM",
        ),
        Recommendation(
            action="Check for preceding failed login spikes",
            reason="Identify if success was preceded by brute force guessing",
            priority="HIGH",
        ),
    ],
    "Privilege Escalation": [
        Recommendation(
            action="Review elevated privileges and permissions",
            reason="Verify legitimacy of permissions granted to affected account",
            priority="CRITICAL",
        ),
        Recommendation(
            action="Audit administrative command history",
            reason="Review privileged commands executed following escalation",
            priority="HIGH",
        ),
        Recommendation(
            action="Check persistence mechanisms",
            reason="Inspect scheduled tasks, services, and unauthorized local admin creation",
            priority="HIGH",
        ),
        Recommendation(
            action="Investigate affected system vulnerability status",
            reason="Identify CVEs (e.g. T1068) allowing local privilege exploitation",
            priority="HIGH",
        ),
    ],
    "SQL Injection Attempt": [
        Recommendation(
            action="Inspect web application firewall (WAF) logs",
            reason="Analyze injected SQL payloads and targeted web parameters",
            priority="HIGH",
        ),
        Recommendation(
            action="Review database query logs",
            reason="Verify if SQL injection caused unauthorized data access or errors",
            priority="CRITICAL",
        ),
        Recommendation(
            action="Apply parameterized queries & input sanitization",
            reason="Remediate public-facing application vulnerability (T1190)",
            priority="HIGH",
        ),
    ],
    "Phishing Email": [
        Recommendation(
            action="Quarantine suspicious message",
            reason="Prevent further interaction across enterprise mailboxes",
            priority="HIGH",
        ),
        Recommendation(
            action="Inspect sender domain & headers against threat intel",
            reason="Evaluate domain age, SPF/DKIM/DMARC alignment, and reputation",
            priority="MEDIUM",
        ),
        Recommendation(
            action="Scan recipient endpoint for secondary payload",
            reason="Confirm no attached malicious files or links were executed",
            priority="HIGH",
        ),
    ],
    "Malware Detection": [
        Recommendation(
            action="Investigate affected endpoint",
            reason="Inspect host exhibiting suspicious process or script execution",
            priority="CRITICAL",
        ),
        Recommendation(
            action="Run comprehensive endpoint malware scan",
            reason="Detect, quarantine, and remove malicious artifacts",
            priority="HIGH",
        ),
        Recommendation(
            action="Investigate file hash in threat intelligence feeds",
            reason="Check known SHA256 signatures for campaign attribution",
            priority="HIGH",
        ),
        Recommendation(
            action="Review active process tree & network connections",
            reason="Identify command & control (C2) communication channels",
            priority="HIGH",
        ),
    ],
    "File Access": [
        Recommendation(
            action="Audit accessed file paths and classification",
            reason="Determine if sensitive, confidential, or proprietary data was accessed",
            priority="HIGH",
        ),
        Recommendation(
            action="Check data egress volume & destination IP",
            reason="Evaluate potential data exfiltration or unauthorized collection (T1083)",
            priority="HIGH",
        ),
        Recommendation(
            action="Review user file permissions",
            reason="Ensure principle of least privilege applies to target repository",
            priority="MEDIUM",
        ),
    ],
    "Port Scan": [
        Recommendation(
            action="Review firewall ingress & egress rules",
            reason="Ensure non-essential external ports are blocked",
            priority="MEDIUM",
        ),
        Recommendation(
            action="Inspect listening services on scanned hosts",
            reason="Verify patch status of discovered active ports (T1046)",
            priority="MEDIUM",
        ),
        Recommendation(
            action="Monitor source IP for subsequent exploitation attempts",
            reason="Track transition from reconnaissance to active exploitation",
            priority="HIGH",
        ),
    ],
    "USB Device Connected": [
        Recommendation(
            action="Verify USB device against authorized hardware registry",
            reason="Check device vendor and product ID against IT whitelist (T1200)",
            priority="HIGH",
        ),
        Recommendation(
            action="Scan connected removable media for malware",
            reason="Ensure device does not contain malicious autorun scripts",
            priority="HIGH",
        ),
        Recommendation(
            action="Audit removable media policy compliance",
            reason="Confirm user authorization for external storage usage",
            priority="MEDIUM",
        ),
    ],
}


def generate_recommendations(
    threat_type: str,
    attack_chain: Optional[AttackChainResult] = None,
    enrichment: Optional[EnrichmentResult] = None,
) -> List[Recommendation]:
    """
    Generate structured, non-destructive advisory response recommendations.

    Parameters
    ----------
    threat_type: str
        The primary threat type (e.g., 'Brute Force', 'Privilege Escalation').
    attack_chain: Optional[AttackChainResult]
        Detected attack chain details, if any.
    enrichment: Optional[EnrichmentResult]
        Asset, CVE, MITRE, and IOC enrichment context.
    """
    results: List[Recommendation] = []

    # 1. Base recommendations from threat catalog
    matched = _RECOMMENDATIONS_CATALOG.get(threat_type)
    if not matched:
        # Check partial/case-insensitive match
        for k, v in _RECOMMENDATIONS_CATALOG.items():
            if k.lower() in threat_type.lower() or threat_type.lower() in k.lower():
                matched = v
                break

    if matched:
        results.extend(matched)
    else:
        # Fallback general recommendations
        results.extend([
            Recommendation(
                action="Review security event context & audit logs",
                reason="Assess anomalous signals and correlated activities",
                priority="MEDIUM",
            ),
            Recommendation(
                action="Monitor associated asset & user account",
                reason="Maintain heightened surveillance for subsequent threat indicators",
                priority="LOW",
            ),
        ])

    # 2. Enrichment-specific recommendations
    if enrichment:
        if enrichment.threat_intel and enrichment.threat_intel.found and enrichment.threat_intel.threat_score:
            if enrichment.threat_intel.threat_score >= 80:
                results.insert(
                    0,
                    Recommendation(
                        action=f"Investigate matched malicious IOC ({enrichment.threat_intel.ioc_value})",
                        reason="Indicator is flagged in Threat Intelligence feeds with high/critical severity",
                        priority="CRITICAL",
                    ),
                )

        if enrichment.vulnerability and enrichment.vulnerability.found and enrichment.vulnerability.cvss_score:
            if enrichment.vulnerability.cvss_score >= 9.0:
                results.append(
                    Recommendation(
                        action=f"Apply critical security patch for {enrichment.vulnerability.cve_id}",
                        reason=f"Asset has an active Critical CVE with CVSS {enrichment.vulnerability.cvss_score}",
                        priority="CRITICAL",
                    ),
                )

    # 3. Attack Chain specific recommendation
    if attack_chain and attack_chain.attack_chain_detected:
        results.insert(
            0,
            Recommendation(
                action=f"Initiate priority investigation for {attack_chain.attack_chain_type}",
                reason=f"Multi-stage correlation confirmed an attack chain across {len(attack_chain.stages)} chronological events.",
                priority="CRITICAL",
            ),
        )

    # Deduplicate actions while preserving order
    seen_actions = set()
    deduped: List[Recommendation] = []
    for r in results:
        if r.action not in seen_actions:
            seen_actions.add(r.action)
            deduped.append(r)

    return deduped
