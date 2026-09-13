"""
risk/correlation.py — Milestone 3 Event Correlation & Attack Chain Detection Engine
===================================================================================
Milestone 3: Risk Prioritization & Security Intelligence

This module provides:
  1. Temporal & contextual event correlation (sliding configurable time window: default 15m)
  2. Multi-stage attack chain detection mapped to real M2 event types
  3. Non-destructive contextual signals for incident prioritization

Attack Chain Validation Rules:
  - Chains require MEANINGFUL CHRONOLOGICAL PROGRESSION of specific event types.
  - Asset-only context is NOT sufficient for chain detection; stronger pivots preferred.
  - Each chain type has minimum stage requirements that must be satisfied.
  - Terminology: "Detected" is used (not "Confirmed") to avoid misrepresenting correlation as proof.

Recognized M2 Event Types (all 10):
  1. Brute Force          → T1110, Credential Access
  2. Failed Login         → T1078, Defense Evasion
  3. Login Success        → T1078, Defense Evasion
  4. Privilege Escalation → T1068, Privilege Escalation
  5. SQL Injection Attempt→ T1190, Initial Access
  6. Phishing Email       → T1566, Initial Access
  7. USB Device Connected → T1200, Initial Access
  8. Port Scan            → T1046, Discovery
  9. File Access          → T1083, Discovery
  10. Malware Detection   → T1059, Execution

Chain Definitions:
  BRUTE FORCE CHAIN:
    - Requires: ≥2 failed/brute-force events + ≥1 Login Success AFTER failed attempts
    - Context: same username OR same source_ip (asset-only NOT sufficient)
    - Chronological: first failed attempt must precede first success

  PRIVILEGE ESCALATION CHAIN:
    - Requires: ≥1 Initial Access event + ≥1 Privilege Escalation event + optionally post-execution
    - Context: same username preferred; OR same source_ip; asset+different-user NOT sufficient alone
    - Chronological: Initial Access must precede Privilege Escalation

  DATA EXFILTRATION CHAIN:
    - Requires: ≥1 Access event + (≥1 Discovery/Lateral + ≥1 Exfil OR ≥2 exfil events)
    - Context: same username OR same source_ip (asset-only NOT sufficient)
    - Chronological: access must precede exfiltration
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import database.mongo_db as mongo_module
from models.m3_schemas import (
    AttackChainResult,
    AttackChainStage,
    CorrelatedEventSummary,
    CorrelationResult,
)

log = logging.getLogger("risk.correlation")

# Default time window in minutes (configurable between 5 and 30 per mentor recommendation)
DEFAULT_CORRELATION_WINDOW_MINUTES = 15

# Real M2 Event Type Mapping to Attack Chain Roles:
# Initial access events
_INITIAL_ACCESS_TYPES = {
    "SQL Injection Attempt",
    "Phishing Email",
    "USB Device Connected",
    "Failed Login",
}

# Discovery / lateral movement events
_DISCOVERY_LATERAL_TYPES = {
    "Port Scan",
    "File Access",
}

# Post-escalation execution / administrative activity
_EXECUTION_ADMIN_TYPES = {
    "Malware Detection",
    "File Access",
    "Login Success",
}

# Failed / brute-force credential events
_BRUTEFORCE_ATTEMPT_TYPES = {
    "Failed Login",
    "Brute Force",
}

# Exfiltration candidates
_EXFIL_TYPES = {
    "File Access",
    "Malware Detection",
}

# Access establishment (for data exfil chain)
_ACCESS_TYPES_FOR_EXFIL = {
    "Login Success",
    "SQL Injection Attempt",
    "Phishing Email",
}

# Minimum required failed events for brute force chain
_BRUTE_FORCE_MIN_ATTEMPTS = 2


def _parse_timestamp(ts: Any) -> Optional[datetime]:
    """Parse string or datetime timestamp into a standard Python datetime."""
    if isinstance(ts, datetime):
        return ts
    if not ts or not isinstance(ts, str):
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
        try:
            return datetime.strptime(ts.strip(), fmt)
        except ValueError:
            continue
    return None


def _format_timestamp(dt: datetime) -> str:
    """Format datetime into standard M2/M3 string timestamp format."""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _has_strong_context(event_a: Dict[str, Any], event_b: Dict[str, Any]) -> bool:
    """
    Check if two events share a strong contextual pivot beyond just asset name.
    Strong context = same username OR same source_ip OR same destination_ip.
    Asset-alone is intentionally NOT considered strong context.
    """
    for field in ("username", "source_ip", "destination_ip"):
        a_val = event_a.get(field)
        b_val = event_b.get(field)
        if (
            a_val and b_val
            and a_val.strip()
            and b_val.strip()
            and a_val.lower() not in ("unknown", "none", "n/a", "")
            and b_val.lower() not in ("unknown", "none", "n/a", "")
            and a_val == b_val
        ):
            return True
    return False


def _events_share_strong_context_with_anchor(
    anchor: Dict[str, Any], events: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Filter events that share strong context (user/IP) with anchor."""
    return [e for e in events if _has_strong_context(anchor, e) or str(e.get("event_id")) == str(anchor.get("event_id"))]


def correlate_events(
    event: Dict[str, Any],
    window_minutes: int = DEFAULT_CORRELATION_WINDOW_MINUTES,
    db: Any = None,
) -> CorrelationResult:
    """
    Correlate a security event with other suspicious/security events sharing
    meaningful context within a configurable time window.

    Contextual attributes inspected:
      - username
      - source_ip
      - destination_ip
      - asset_name
    """
    if db is None:
        db = mongo_module.mongo.get_database()

    event_id = event.get("event_id")
    raw_ts = event.get("timestamp")
    dt = _parse_timestamp(raw_ts)

    if not dt:
        return CorrelationResult(
            related_event_ids=[],
            related_events_count=0,
            correlation_keys=[],
            time_window_minutes=window_minutes,
            chronological_events=[],
        )

    t_start = dt - timedelta(minutes=window_minutes)
    t_end = dt + timedelta(minutes=window_minutes)
    t_start_str = _format_timestamp(t_start)
    t_end_str = _format_timestamp(t_end)

    # Build shared-context match conditions
    context_or_clauses: List[Dict[str, Any]] = []
    correlation_keys: List[str] = []

    username = event.get("username")
    if username and username.strip() and username.lower() not in ("unknown", "none", "n/a"):
        context_or_clauses.append({"username": username})
        correlation_keys.append(f"username:{username}")

    source_ip = event.get("source_ip")
    if source_ip and source_ip.strip() and source_ip.lower() not in ("unknown", "none", "n/a"):
        context_or_clauses.append({"source_ip": source_ip})
        correlation_keys.append(f"source_ip:{source_ip}")

    dest_ip = event.get("destination_ip")
    if dest_ip and dest_ip.strip() and dest_ip.lower() not in ("unknown", "none", "n/a"):
        context_or_clauses.append({"destination_ip": dest_ip})
        correlation_keys.append(f"destination_ip:{dest_ip}")

    asset_name = event.get("asset_name")
    if asset_name and asset_name.strip() and asset_name.lower() not in ("unknown", "none", "n/a"):
        context_or_clauses.append({"asset_name": asset_name})
        correlation_keys.append(f"asset_name:{asset_name}")

    if not context_or_clauses:
        return CorrelationResult(
            related_event_ids=[],
            related_events_count=0,
            correlation_keys=[],
            time_window_minutes=window_minutes,
            chronological_events=[],
        )

    query: Dict[str, Any] = {
        "timestamp": {"$gte": t_start_str, "$lte": t_end_str},
        "$or": context_or_clauses,
    }
    if event_id:
        query["event_id"] = {"$ne": event_id}

    cursor = db["security_events"].find(query).sort("timestamp", 1).limit(50)
    related_docs = list(cursor)

    related_event_ids: List[str] = []
    summaries: List[CorrelatedEventSummary] = []

    for doc in related_docs:
        eid = str(doc.get("event_id", ""))
        if eid and eid not in related_event_ids:
            related_event_ids.append(eid)
            summaries.append(
                CorrelatedEventSummary(
                    event_id=eid,
                    timestamp=str(doc.get("timestamp", "")),
                    event_type=str(doc.get("event_type", "Unknown")),
                    username=doc.get("username"),
                    source_ip=doc.get("source_ip"),
                    destination_ip=doc.get("destination_ip"),
                    asset_name=doc.get("asset_name"),
                    severity=doc.get("severity"),
                )
            )

    return CorrelationResult(
        related_event_ids=related_event_ids,
        related_events_count=len(related_event_ids),
        correlation_keys=correlation_keys,
        time_window_minutes=window_minutes,
        chronological_events=summaries,
    )


def _make_stage(
    order: int,
    stage_name: str,
    event: Dict[str, Any],
    tactic_default: str = "",
    tech_id_default: Optional[str] = None,
    tech_name_default: Optional[str] = None,
) -> AttackChainStage:
    return AttackChainStage(
        stage_order=order,
        stage_name=stage_name,
        event_id=str(event.get("event_id")),
        event_type=str(event.get("event_type", "Unknown")),
        timestamp=str(event.get("timestamp", "")),
        tactic=event.get("tactic") or tactic_default,
        technique_id=event.get("technique_id") or tech_id_default,
        technique_name=event.get("technique_name") or tech_name_default,
    )


def _detect_brute_force_chain(
    anchor_id: str,
    ev_list: List[Dict[str, Any]],
    anchor_event: Dict[str, Any],
) -> Optional[AttackChainResult]:
    """
    Brute Force Chain Detection.

    Requirements:
      - At least 2 failed/brute-force events
      - At least 1 Login Success occurring AFTER the failed attempts
      - Events must share strong context (username or source_ip) with anchor
      - Chronological: first failed attempt must precede first login success
    """
    # Filter to events with strong context (username or source_ip) — asset-only NOT sufficient
    strong_ctx = _events_share_strong_context_with_anchor(anchor_event, ev_list)

    failed_attempts = sorted(
        [e for e in strong_ctx if e.get("event_type") in _BRUTEFORCE_ATTEMPT_TYPES],
        key=lambda e: str(e.get("timestamp", ""))
    )
    login_successes = sorted(
        [e for e in strong_ctx if e.get("event_type") == "Login Success"],
        key=lambda e: str(e.get("timestamp", ""))
    )

    # Requirement 1: at least 2 failed/brute-force events
    if len(failed_attempts) < _BRUTE_FORCE_MIN_ATTEMPTS:
        return None

    # Requirement 2: at least 1 login success
    if not login_successes:
        return None

    # Requirement 3: chronological order - first failed attempt must precede first success
    t_first_fail = _parse_timestamp(failed_attempts[0].get("timestamp"))
    t_first_success = _parse_timestamp(login_successes[0].get("timestamp"))
    if not t_first_fail or not t_first_success:
        return None
    if t_first_fail >= t_first_success:
        return None  # Success before failures — not a valid brute force progression

    # Build stages
    stages = []
    seen_eids = set()

    for e in failed_attempts:
        eid = str(e.get("event_id"))
        if eid not in seen_eids:
            seen_eids.add(eid)
            stages.append(_make_stage(0, "Credential Access Attempt", e, "Credential Access", "T1110", "Brute Force"))

    for e in login_successes:
        eid = str(e.get("event_id"))
        if eid not in seen_eids:
            seen_eids.add(eid)
            stages.append(_make_stage(0, "Successful Account Access", e, "Defense Evasion", "T1078", "Valid Accounts"))

    # Anchor must participate
    chain_eids = [s.event_id for s in stages]
    if anchor_id not in chain_eids:
        return None

    stages.sort(key=lambda s: s.timestamp)
    for idx, s in enumerate(stages, 1):
        s.stage_order = idx

    return AttackChainResult(
        attack_chain_id=f"AC-{anchor_id}",
        attack_chain_detected=True,
        attack_chain_type="Brute Force Chain",
        confidence="High" if len(stages) >= 3 else "Medium",
        description=f"Detected repeated credential attempts followed by successful login ({len(stages)} stages).",
        stages=stages,
        event_ids=[s.event_id for s in stages],
        timeline=[
            {"stage": s.stage_name, "event_id": s.event_id, "timestamp": s.timestamp, "event_type": s.event_type}
            for s in stages
        ],
    )


def _detect_privilege_escalation_chain(
    anchor_id: str,
    ev_list: List[Dict[str, Any]],
    anchor_event: Dict[str, Any],
) -> Optional[AttackChainResult]:
    """
    Privilege Escalation Chain Detection.

    Requirements:
      - At least 1 Initial Access event
      - At least 1 Privilege Escalation event
      - Initial Access must chronologically precede Privilege Escalation
      - Events must share strong context (username or source_ip)
        Asset-only match is NOT sufficient when users/IPs are different
    """
    # Filter to events with strong context — asset-only NOT sufficient
    strong_ctx = _events_share_strong_context_with_anchor(anchor_event, ev_list)

    initial_acc = sorted(
        [e for e in strong_ctx if e.get("event_type") in _INITIAL_ACCESS_TYPES],
        key=lambda e: str(e.get("timestamp", ""))
    )
    priv_esc = sorted(
        [e for e in strong_ctx if e.get("event_type") == "Privilege Escalation"],
        key=lambda e: str(e.get("timestamp", ""))
    )
    post_exec = sorted(
        [e for e in strong_ctx if e.get("event_type") in _EXECUTION_ADMIN_TYPES and e.get("event_type") != "Privilege Escalation"],
        key=lambda e: str(e.get("timestamp", ""))
    )

    # Requirement 1: at least one initial access and one privilege escalation
    if not initial_acc or not priv_esc:
        return None

    # Requirement 2: chronological — first initial access must precede first privilege escalation
    t_first_initial = _parse_timestamp(initial_acc[0].get("timestamp"))
    t_first_privesc = _parse_timestamp(priv_esc[0].get("timestamp"))
    if not t_first_initial or not t_first_privesc:
        return None
    if t_first_initial >= t_first_privesc:
        return None  # Escalation before initial access — invalid chain

    # Build stages
    stages = []
    seen_eids = set()

    for e in initial_acc:
        eid = str(e.get("event_id"))
        if eid not in seen_eids:
            seen_eids.add(eid)
            stages.append(_make_stage(0, "Initial Access / Foothold", e, "Initial Access"))

    for e in priv_esc:
        eid = str(e.get("event_id"))
        if eid not in seen_eids:
            seen_eids.add(eid)
            stages.append(_make_stage(0, "Privilege Escalation", e, "Privilege Escalation", "T1068", "Exploitation for Privilege Escalation"))

    for e in post_exec:
        eid = str(e.get("event_id"))
        if eid not in seen_eids:
            seen_eids.add(eid)
            stages.append(_make_stage(0, "Post-Escalation Execution / Activity", e, "Execution"))

    # Anchor must participate
    chain_eids = [s.event_id for s in stages]
    if anchor_id not in chain_eids:
        return None

    if len(stages) < 2:
        return None

    stages.sort(key=lambda s: s.timestamp)
    for idx, s in enumerate(stages, 1):
        s.stage_order = idx

    return AttackChainResult(
        attack_chain_id=f"AC-{anchor_id}",
        attack_chain_detected=True,
        attack_chain_type="Privilege Escalation Chain",
        confidence="High" if len(stages) >= 3 else "Medium",
        description=f"Detected multi-stage privilege escalation progression ({len(stages)} stages).",
        stages=stages,
        event_ids=[s.event_id for s in stages],
        timeline=[
            {"stage": s.stage_name, "event_id": s.event_id, "timestamp": s.timestamp, "event_type": s.event_type}
            for s in stages
        ],
    )


def _detect_data_exfiltration_chain(
    anchor_id: str,
    ev_list: List[Dict[str, Any]],
    anchor_event: Dict[str, Any],
) -> Optional[AttackChainResult]:
    """
    Data Exfiltration Chain Detection.

    Requirements:
      - At least 1 Access establishment event
      - At least 1 Discovery/Lateral Movement OR at least 2 Exfil events
      - At least 1 Exfiltration event occurring AFTER access
      - Events must share strong context (username or source_ip)
        Asset-only match is NOT sufficient when users/IPs are different
    """
    # Filter to events with strong context — asset-only NOT sufficient
    strong_ctx = _events_share_strong_context_with_anchor(anchor_event, ev_list)

    access_evts = sorted(
        [e for e in strong_ctx if e.get("event_type") in _ACCESS_TYPES_FOR_EXFIL],
        key=lambda e: str(e.get("timestamp", ""))
    )
    disc_evts = sorted(
        [e for e in strong_ctx if e.get("event_type") in _DISCOVERY_LATERAL_TYPES],
        key=lambda e: str(e.get("timestamp", ""))
    )
    exfil_evts = sorted(
        [e for e in strong_ctx if e.get("event_type") in _EXFIL_TYPES],
        key=lambda e: str(e.get("timestamp", ""))
    )

    # Requirement: access + (discovery or ≥2 exfil) + exfil
    if not access_evts:
        return None
    if not exfil_evts:
        return None
    discovery_or_multi_exfil = disc_evts or len(exfil_evts) >= 2
    if not discovery_or_multi_exfil:
        return None

    # Chronological: first access must precede first exfil
    t_first_access = _parse_timestamp(access_evts[0].get("timestamp"))
    t_first_exfil = _parse_timestamp(exfil_evts[0].get("timestamp"))
    if not t_first_access or not t_first_exfil:
        return None
    if t_first_access >= t_first_exfil:
        return None  # Exfil before access — invalid chain

    # Build stages
    stages = []
    seen_eids = set()

    for e in access_evts:
        eid = str(e.get("event_id"))
        if eid not in seen_eids:
            seen_eids.add(eid)
            stages.append(_make_stage(0, "Access Establishment", e, "Initial Access"))

    for e in disc_evts:
        eid = str(e.get("event_id"))
        if eid not in seen_eids:
            seen_eids.add(eid)
            stages.append(_make_stage(0, "Internal Discovery & Reconnaissance", e, "Discovery"))

    for e in exfil_evts:
        eid = str(e.get("event_id"))
        if eid not in seen_eids:
            seen_eids.add(eid)
            stages.append(_make_stage(0, "Data Staging & Exfiltration Activity", e, "Exfiltration"))

    # Anchor must participate
    chain_eids = [s.event_id for s in stages]
    if anchor_id not in chain_eids:
        return None

    if len(stages) < 2:
        return None

    stages.sort(key=lambda s: s.timestamp)
    for idx, s in enumerate(stages, 1):
        s.stage_order = idx

    return AttackChainResult(
        attack_chain_id=f"AC-{anchor_id}",
        attack_chain_detected=True,
        attack_chain_type="Data Exfiltration Chain",
        confidence="High" if len(stages) >= 3 else "Medium",
        description=f"Detected access establishment followed by exfiltration activity ({len(stages)} stages).",
        stages=stages,
        event_ids=[s.event_id for s in stages],
        timeline=[
            {"stage": s.stage_name, "event_id": s.event_id, "timestamp": s.timestamp, "event_type": s.event_type}
            for s in stages
        ],
    )


def detect_attack_chain(
    anchor_event: Dict[str, Any],
    correlated_events: Optional[List[Dict[str, Any]]] = None,
) -> AttackChainResult:
    """
    Evaluate anchor event and associated correlated events to detect canonical multi-stage attack chains.

    Recognized patterns (in order of check):
      1. BRUTE FORCE: ≥2 Failed Login/Brute Force → Login Success (strong context required)
      2. PRIVILEGE ESCALATION: Initial Access → Privilege Escalation → optional post-exec (strong context required)
      3. DATA EXFILTRATION: Access → Discovery/Lateral → Exfil (strong context required)

    Invariants:
      - The attack chain MUST include the anchor event as an active stage.
      - All chains require strong contextual continuity (username or source_ip).
      - Asset-alone match will NOT trigger a chain when users and IPs differ.
      - Stages must occur in chronological order as defined by each chain type.
      - Terminology: "Detected" is used (not "Confirmed") to reflect correlation confidence.
    """
    anchor_id = str(anchor_event.get("event_id"))

    all_candidates = [dict(anchor_event)]
    if correlated_events:
        for ce in correlated_events:
            if str(ce.get("event_id")) != anchor_id:
                all_candidates.append(dict(ce))

    all_candidates.sort(key=lambda ev: str(ev.get("timestamp", "")))

    if len(all_candidates) < 2:
        return AttackChainResult(attack_chain_detected=False)

    # Try each chain type in order of precedence
    # 1. Brute Force
    result = _detect_brute_force_chain(anchor_id, all_candidates, anchor_event)
    if result:
        return result

    # 2. Privilege Escalation
    result = _detect_privilege_escalation_chain(anchor_id, all_candidates, anchor_event)
    if result:
        return result

    # 3. Data Exfiltration
    result = _detect_data_exfiltration_chain(anchor_id, all_candidates, anchor_event)
    if result:
        return result

    return AttackChainResult(attack_chain_detected=False)
