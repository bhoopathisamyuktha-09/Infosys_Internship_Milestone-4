"""
tests/test_m3_backend.py — Milestone 3 Comprehensive Backend Test Suite
========================================================================
Milestone 3: Risk Prioritization & Security Intelligence

Tests cover:
  1. Event Correlation (shared context, sliding window, negative cases)
  2. Attack Chain Detection (Brute Force, Privilege Escalation, Data Exfiltration)
  3. Advisory Recommendations (Threat-specific, enrichment-tailored, non-destructive)
  4. Incident Repository & Lifecycle (CRUD, Valid & Invalid status updates, aggregations)
  5. Deterministic Risk Engine & Mentor Acceptance Value (Score 93)
  6. All 7 M3 REST API Endpoints via FastAPI TestClient
"""

import os
import sys
from datetime import datetime, timezone

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import mongomock
import pytest
from fastapi.testclient import TestClient

from database.incident_repository import (
    create_incident,
    ensure_incident_indexes,
    get_attack_chains,
    get_high_risk_incidents,
    get_incident_by_anchor_event_id,
    get_incident_by_id,
    get_incident_recommendations,
    get_risk_summary,
    list_incidents,
    update_incident_status,
)
from database.mongo_db import MongoDatabase
from main import app
from models.m3_schemas import EnrichmentResult
from risk.correlation import correlate_events, detect_attack_chain
from risk.enrichment import enrich_event
from risk.recommendations import generate_recommendations
from risk.risk_score import calculate_risk
from services.data_store import store
from services.incident_service import process_event_to_incident


def _setup_mock_environment():
    """Create isolated mock MongoDB client and bind to global database singleton."""
    mock_client = mongomock.MongoClient()
    mock_db = mock_client["threat_detection"]

    # 1. Assets
    mock_db["assets"].insert_many([
        {"asset_id": "AST002", "asset_name": "Database-01", "criticality": "Critical"},
        {"asset_id": "AST001", "asset_name": "WebServer", "criticality": "High"},
        {"asset_id": "AST004", "asset_name": "Finance-PC-02", "criticality": "Medium"},
    ])

    # 2. Vulnerabilities
    mock_db["vulnerabilities"].insert_many([
        {"cve_id": "CVE-2023-1234", "cvss_score": 9.8},
        {"cve_id": "CVE-2024-1045", "cvss_score": 5.4},
    ])

    # 3. MITRE mapping
    mock_db["mitre_attack_mapping"].insert_many([
        {"event_type": "Brute Force", "technique_id": "T1110", "technique_name": "Brute Force", "tactic": "Credential Access"},
        {"event_type": "Failed Login", "technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Defense Evasion"},
        {"event_type": "Login Success", "technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Defense Evasion"},
        {"event_type": "Privilege Escalation", "technique_id": "T1068", "technique_name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
        {"event_type": "SQL Injection Attempt", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"event_type": "Malware Detection", "technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactic": "Execution"},
        {"event_type": "File Access", "technique_id": "T1083", "technique_name": "File and Directory Discovery", "tactic": "Discovery"},
        {"event_type": "Port Scan", "technique_id": "T1046", "technique_name": "Network Service Discovery", "tactic": "Discovery"},
    ])

    # 4. Threat Intel
    mock_db["threat_intelligence"].insert_many([
        {
            "indicator_value": "192.0.2.1",
            "indicator_type": "IP Address",
            "threat_name": "Brute Force Campaign",
            "threat_actor": "APT-Test-Group",
            "confidence": "High",
            "severity": "High",
        },
        {
            "indicator_value": "198.51.100.1",
            "indicator_type": "IP Address",
            "threat_name": "Malware Distribution Network",
            "threat_actor": "Unknown",
            "confidence": "Critical",
            "severity": "Critical",
        },
        {
            "indicator_value": "10.0.5.208",   # destination_ip for testing dest lookup
            "indicator_type": "IP Address",
            "threat_name": "C2 Callback Campaign",
            "threat_actor": "TA-Desttest",
            "confidence": "Medium",
            "severity": "High",
        },
    ])

    # 5. Security Events for correlation & incident testing
    mock_db["security_events"].insert_many([
        {
            "event_id": "EVT000001",
            "timestamp": "2025-08-03 08:10:00",
            "source_ip": "192.0.2.1",
            "destination_ip": "10.0.5.208",
            "event_type": "Brute Force",
            "username": "admin",
            "severity": "High",
            "severity_score": 3,
            "vulnerability_id": "CVE-2023-1234",
            "cvss_score": 9.8,
            "asset_name": "Database-01",
            "technique_id": "T1110",
        },
        {
            "event_id": "EVT000002",
            "timestamp": "2025-08-03 08:18:00",
            "source_ip": "192.0.2.1",
            "destination_ip": "10.0.5.208",
            "event_type": "Login Success",
            "username": "admin",
            "severity": "High",
            "severity_score": 3,
            "asset_name": "Database-01",
            "technique_id": "T1078",
        },
        {
            "event_id": "EVT000003",
            "timestamp": "2025-08-03 12:00:00",
            "source_ip": "192.0.2.1",
            "destination_ip": "10.0.5.208",
            "event_type": "Login Success",
            "username": "admin",
            "severity": "Low",
            "severity_score": 1,
            "asset_name": "Database-01",
        },
    ])

    # 6. M2 Threat Predictions
    mock_db["threat_predictions"].insert_many([
        {
            "prediction_id": "PRED_TEST_001",
            "event_id": "EVT000001",
            "verdict": "Critical",
            "confidence_score": 91.0,
            "predicted_threat_type": "Brute Force",
            "anomaly_score": -0.72,
            "rule_score": 85,
        },
    ])

    # Patch global singleton
    mongo_instance = MongoDatabase()
    mongo_instance.client = mock_client
    mongo_instance.db = mock_db
    mongo_instance._connected = True

    from database import mongo_db
    mongo_db.mongo = mongo_instance

    store._loaded = False
    store.load()
    ensure_incident_indexes(mock_db)

    return mock_db


@pytest.fixture(autouse=True)
def setup_test_db():
    return _setup_mock_environment()


# ── 1. Event Correlation Tests ────────────────────────────────────────────────

def test_correlation_same_user_and_ip_within_window(setup_test_db):
    db = setup_test_db
    anchor = db["security_events"].find_one({"event_id": "EVT000001"})
    result = correlate_events(anchor, window_minutes=15, db=db)

    assert result.related_events_count >= 1
    assert "EVT000002" in result.related_event_ids
    assert any("username:admin" in k for k in result.correlation_keys)
    assert any("source_ip:192.0.2.1" in k for k in result.correlation_keys)


def test_correlation_outside_window_excluded(setup_test_db):
    db = setup_test_db
    anchor = db["security_events"].find_one({"event_id": "EVT000001"})
    result = correlate_events(anchor, window_minutes=15, db=db)

    # EVT000003 is ~4 hours away -> should not be correlated
    assert "EVT000003" not in result.related_event_ids


def test_correlation_unrelated_event(setup_test_db):
    db = setup_test_db
    unrelated = {
        "event_id": "EVT999999",
        "timestamp": "2025-08-03 08:12:00",
        "username": "unique_user_xyz",
        "source_ip": "198.51.100.99",
        "destination_ip": "10.0.9.99",
        "asset_name": "Unrelated-PC",
    }
    result = correlate_events(unrelated, window_minutes=15, db=db)
    assert result.related_events_count == 0
    assert len(result.related_event_ids) == 0


# ── 2. Attack Chain Detection Tests ───────────────────────────────────────────

def test_attack_chain_brute_force_valid():
    """Valid BF: 2+ failed attempts, 1 success AFTER, shared username."""
    anchor = {
        "event_id": "EVT_BF_01",
        "timestamp": "2025-08-03 08:00:00",
        "event_type": "Brute Force",
        "username": "admin",
    }
    correlated = [
        {
            "event_id": "EVT_BF_02",
            "timestamp": "2025-08-03 08:02:00",
            "event_type": "Failed Login",
            "username": "admin",
        },
        {
            "event_id": "EVT_BF_03",
            "timestamp": "2025-08-03 08:05:00",
            "event_type": "Login Success",
            "username": "admin",
        },
    ]
    chain = detect_attack_chain(anchor, correlated)
    assert chain.attack_chain_detected is True
    assert chain.attack_chain_type == "Brute Force Chain"
    assert chain.attack_chain_id == "AC-EVT_BF_01"
    assert chain.confidence == "High"
    assert len(chain.stages) == 3
    assert "EVT_BF_01" in chain.event_ids
    assert "EVT_BF_03" in chain.event_ids


def test_attack_chain_brute_force_invalid_only_one_failed():
    """Invalid BF: only 1 failed attempt — does not meet min 2 requirement."""
    anchor = {
        "event_id": "EVT_BF_SINGLE",
        "timestamp": "2025-08-03 08:00:00",
        "event_type": "Brute Force",
        "username": "admin",
    }
    correlated = [
        {
            "event_id": "EVT_BF_SUC",
            "timestamp": "2025-08-03 08:05:00",
            "event_type": "Login Success",
            "username": "admin",
        },
    ]
    chain = detect_attack_chain(anchor, correlated)
    # Only 1 failed attempt + 1 success — not valid BF chain (requires >= 2 attempts)
    assert chain.attack_chain_detected is False or chain.attack_chain_type != "Brute Force Chain"


def test_attack_chain_brute_force_invalid_wrong_order():
    """Invalid BF: success appears before failed attempts — not a valid progression."""
    anchor = {
        "event_id": "EVT_BF_WRONG",
        "timestamp": "2025-08-03 08:05:00",
        "event_type": "Brute Force",
        "username": "admin",
    }
    correlated = [
        {
            "event_id": "EVT_BF_FAIL2",
            "timestamp": "2025-08-03 08:04:00",
            "event_type": "Failed Login",
            "username": "admin",
        },
        {
            "event_id": "EVT_BF_SUCCESS_EARLY",
            "timestamp": "2025-08-03 07:55:00",  # success BEFORE failures
            "event_type": "Login Success",
            "username": "admin",
        },
    ]
    chain = detect_attack_chain(anchor, correlated)
    # Login Success happened before failed attempts — not a valid BF chain
    assert chain.attack_chain_detected is False or chain.attack_chain_type != "Brute Force Chain"


def test_attack_chain_privilege_escalation_valid():
    """Valid PE: initial access → privilege escalation with shared username, in order."""
    anchor = {
        "event_id": "EVT_PE_01",
        "timestamp": "2025-08-03 08:00:00",
        "event_type": "SQL Injection Attempt",
        "username": "attacker",
    }
    correlated = [
        {
            "event_id": "EVT_PE_02",
            "timestamp": "2025-08-03 08:06:00",
            "event_type": "Privilege Escalation",
            "username": "attacker",
        },
        {
            "event_id": "EVT_PE_03",
            "timestamp": "2025-08-03 08:10:00",
            "event_type": "Malware Detection",
            "username": "attacker",
        },
    ]
    chain = detect_attack_chain(anchor, correlated)
    assert chain.attack_chain_detected is True
    assert chain.attack_chain_type == "Privilege Escalation Chain"
    assert chain.attack_chain_id == "AC-EVT_PE_01"
    assert chain.confidence == "High"
    assert len(chain.stages) == 3


def test_attack_chain_privilege_escalation_invalid_missing_initial():
    """Invalid PE: privilege escalation without initial access — incomplete chain."""
    anchor = {
        "event_id": "EVT_PE_NOINI",
        "timestamp": "2025-08-03 08:00:00",
        "event_type": "Privilege Escalation",
        "username": "attacker",
    }
    correlated = [
        {
            "event_id": "EVT_PE_POST",
            "timestamp": "2025-08-03 08:05:00",
            "event_type": "Malware Detection",
            "username": "attacker",
        }
    ]
    chain = detect_attack_chain(anchor, correlated)
    # No initial access event → no privilege escalation chain
    assert chain.attack_chain_detected is False or chain.attack_chain_type != "Privilege Escalation Chain"


def test_attack_chain_asset_only_no_chain():
    """Asset-only match should NOT automatically create a chain when users and IPs differ."""
    anchor = {
        "event_id": "EVT_ASSET_1",
        "timestamp": "2025-08-03 08:00:00",
        "event_type": "SQL Injection Attempt",
        "username": "user_a",
        "source_ip": "10.1.1.1",
        "asset_name": "WebServer",
    }
    correlated = [
        {
            "event_id": "EVT_ASSET_2",
            "timestamp": "2025-08-03 08:05:00",
            "event_type": "Privilege Escalation",
            "username": "user_b",   # Different user
            "source_ip": "10.2.2.2",  # Different IP
            "asset_name": "WebServer",  # Same asset
        }
    ]
    chain = detect_attack_chain(anchor, correlated)
    # Different user and different IP — asset match alone must NOT create a chain
    assert chain.attack_chain_detected is False


def test_attack_chain_anchor_must_participate():
    """Chain must include the anchor event; if anchor is excluded, no chain should be returned."""
    anchor = {
        "event_id": "EVT_ANCHOR_EXCLUDED",
        "timestamp": "2025-08-03 07:00:00",
        "event_type": "Port Scan",  # Not part of BF or PE chain roles
        "username": "admin",
    }
    correlated = [
        {
            "event_id": "EVT_BF_F1",
            "timestamp": "2025-08-03 07:02:00",
            "event_type": "Failed Login",
            "username": "admin",
        },
        {
            "event_id": "EVT_BF_F2",
            "timestamp": "2025-08-03 07:03:00",
            "event_type": "Brute Force",
            "username": "admin",
        },
        {
            "event_id": "EVT_BF_S1",
            "timestamp": "2025-08-03 07:05:00",
            "event_type": "Login Success",
            "username": "admin",
        },
    ]
    chain = detect_attack_chain(anchor, correlated)
    # Port Scan anchor is not in BF chain — anchor must participate
    assert chain.attack_chain_detected is False


def test_attack_chain_data_exfiltration_valid():
    """Valid DE: access establishment → discovery → exfiltration with shared username."""
    anchor = {
        "event_id": "EVT_EX_01",
        "timestamp": "2025-08-03 08:00:00",
        "event_type": "Login Success",
        "username": "hacker",
    }
    correlated = [
        {
            "event_id": "EVT_EX_02",
            "timestamp": "2025-08-03 08:05:00",
            "event_type": "Port Scan",
            "username": "hacker",
        },
        {
            "event_id": "EVT_EX_03",
            "timestamp": "2025-08-03 08:12:00",
            "event_type": "File Access",
            "username": "hacker",
        },
    ]
    chain = detect_attack_chain(anchor, correlated)
    assert chain.attack_chain_detected is True
    assert chain.attack_chain_type == "Data Exfiltration Chain"
    assert chain.attack_chain_id == "AC-EVT_EX_01"
    assert chain.confidence == "High"
    assert len(chain.stages) == 3


def test_attack_chain_random_same_asset_no_chain():
    """Random events on same asset with unrelated users/IPs should NOT form a chain."""
    anchor = {
        "event_id": "EVT_RANDOM_1",
        "timestamp": "2025-08-03 08:00:00",
        "event_type": "File Access",
        "username": "user_x",
        "source_ip": "10.5.5.5",
        "asset_name": "FileServer",
    }
    correlated = [
        {
            "event_id": "EVT_RANDOM_2",
            "timestamp": "2025-08-03 08:03:00",
            "event_type": "Port Scan",
            "username": "user_y",      # Different user
            "source_ip": "10.6.6.6",   # Different IP
            "asset_name": "FileServer",
        },
        {
            "event_id": "EVT_RANDOM_3",
            "timestamp": "2025-08-03 08:08:00",
            "event_type": "Malware Detection",
            "username": "user_z",      # Different user
            "source_ip": "10.7.7.7",   # Different IP
            "asset_name": "FileServer",
        },
    ]
    chain = detect_attack_chain(anchor, correlated)
    # All different users/IPs on same asset — should NOT trigger any chain
    assert chain.attack_chain_detected is False


def test_attack_chain_negative_single_event():
    anchor = {
        "event_id": "EVT_SINGLE_01",
        "timestamp": "2025-08-03 08:00:00",
        "event_type": "Port Scan",
        "username": "user",
    }
    chain = detect_attack_chain(anchor, [])
    assert chain.attack_chain_detected is False


# ── 3. Advisory Recommendations Tests ─────────────────────────────────────────

def test_recommendations_brute_force():
    recs = generate_recommendations("Brute Force")
    assert len(recs) >= 3
    actions = [r.action.lower() for r in recs]
    assert any("source ip" in a for a in actions)
    assert any("authentication" in a for a in actions)


def test_recommendations_privilege_escalation():
    recs = generate_recommendations("Privilege Escalation")
    actions = [r.action.lower() for r in recs]
    assert any("privileges" in a for a in actions)
    assert any("persistence" in a for a in actions)


def test_recommendations_non_destructive():
    for threat in ("Brute Force", "Malware Detection", "Privilege Escalation", "File Access"):
        recs = generate_recommendations(threat)
        for r in recs:
            # Confirm advisory language, no destructive automated commands
            assert "delete" not in r.action.lower()
            assert "format" not in r.action.lower()


# ── 4. Incident Repository & Lifecycle Tests ──────────────────────────────────

def test_incident_repository_crud(setup_test_db):
    db = setup_test_db
    inc_data = {
        "incident_id": "INC-TEST-001",
        "anchor_event_id": "EVT000001",
        "event_ids": ["EVT000001"],
        "threat_type": "Brute Force",
        "risk_score": 93,
        "risk_level": "Critical",
        "priority": "CRITICAL_IMMEDIATE",
        "asset_name": "Database-01",
        "ml_confidence": 91.0,
        "anomaly_score": -0.72,
        "attack_chain_detected": True,
        "status": "Open",
        "created_at": "2025-08-03T08:10:00Z",
    }
    created = create_incident(inc_data, db=db)
    assert created["incident_id"] == "INC-TEST-001"

    fetched = get_incident_by_id("INC-TEST-001", db=db)
    assert fetched is not None
    assert fetched["risk_score"] == 93

    # Status transitions
    updated = update_incident_status("INC-TEST-001", "Investigating", db=db)
    assert updated["status"] == "Investigating"

    updated = update_incident_status("INC-TEST-001", "Resolved", db=db)
    assert updated["status"] == "Resolved"

    updated = update_incident_status("INC-TEST-001", "False Positive", db=db)
    assert updated["status"] == "False Positive"

    with pytest.raises(ValueError):
        update_incident_status("INC-TEST-001", "InvalidStatus", db=db)


def test_incident_repository_aggregations(setup_test_db):
    db = setup_test_db
    create_incident({"incident_id": "INC-01", "anchor_event_id": "E1", "event_ids": ["E1"], "threat_type": "BF", "risk_score": 90, "risk_level": "Critical", "priority": "CRITICAL_IMMEDIATE", "ml_confidence": 90, "anomaly_score": 0, "status": "Open", "created_at": "2025-08-03T00:00:00Z", "attack_chain_detected": True}, db=db)
    create_incident({"incident_id": "INC-02", "anchor_event_id": "E2", "event_ids": ["E2"], "threat_type": "PE", "risk_score": 75, "risk_level": "High", "priority": "HIGH_IMMEDIATE", "ml_confidence": 80, "anomaly_score": 0, "status": "Investigating", "created_at": "2025-08-03T00:00:00Z", "attack_chain_detected": False}, db=db)
    create_incident({"incident_id": "INC-03", "anchor_event_id": "E3", "event_ids": ["E3"], "threat_type": "SCAN", "risk_score": 25, "risk_level": "Medium", "priority": "MEDIUM", "ml_confidence": 40, "anomaly_score": 0, "status": "Resolved", "created_at": "2025-08-03T00:00:00Z", "attack_chain_detected": False}, db=db)

    summary = get_risk_summary(db=db)
    assert summary["total_incidents"] == 3
    assert summary["critical_count"] == 1
    assert summary["high_count"] == 1
    assert summary["medium_count"] == 1
    assert summary["open_count"] == 1
    assert summary["investigating_count"] == 1
    assert summary["resolved_count"] == 1

    high_risk, hr_total = get_high_risk_incidents(min_score=61, db=db)
    assert hr_total == 2
    assert len(high_risk) == 2
    assert high_risk[0]["risk_score"] >= high_risk[1]["risk_score"]

    chains, chains_total = get_attack_chains(db=db)
    assert chains_total == 1
    assert len(chains) == 1
    assert chains[0]["incident_id"] == "INC-01"


# ── 5. End-to-End Orchestration & Mentor Acceptance (Score 93) ────────────────

def test_e2e_incident_service_and_mentor_acceptance(setup_test_db):
    db = setup_test_db
    # EVT000001 in setup_test_db:
    # Threat Severity: 3 -> normalized to 75 (or let's evaluate with mentor inputs:
    # ThreatSev 90, ML 91, Critical Asset 100, CVSS 98, ThreatIntel 80 -> Score 93)
    incident = process_event_to_incident("EVT000001", db=db, persist=True)

    assert incident is not None
    assert incident["incident_id"] == "INC-000001"
    assert incident["anchor_event_id"] == "EVT000001"
    assert incident["threat_type"] == "Brute Force"
    assert incident["ml_confidence"] == 91.0
    assert incident["cvss_score"] == 9.8
    assert incident["ioc_status"] == "Malicious"
    assert incident["related_events_count"] >= 1
    assert len(incident["reasons"]) > 0
    assert len(incident["recommendations"]) > 0
    assert incident["status"] == "Open"

    # Direct mentor acceptance calculation verification
    enrichment = enrich_event({
        "asset_name": "Database-01",
        "vulnerability_id": "CVE-2023-1234",
        "source_ip": "192.0.2.1",
        "event_type": "Brute Force",
    })
    risk_res = calculate_risk(enrichment, ml_confidence=91, threat_severity=90)
    assert risk_res.score == 93
    assert risk_res.level == "Critical"
    assert risk_res.priority == "CRITICAL_IMMEDIATE"


# ── 6. FastAPI REST APIs Tests ────────────────────────────────────────────────

def test_api_risk_calculate(setup_test_db):
    client = TestClient(app)
    resp = client.post("/api/v1/risk/calculate", json={"event_id": "EVT000001"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["event_id"] == "EVT000001"
    assert "risk_score" in data
    assert "risk_level" in data
    assert "priority" in data
    assert "risk_breakdown" in data
    assert "reasons" in data


def test_api_risk_calculate_invalid_event():
    client = TestClient(app)
    resp = client.post("/api/v1/risk/calculate", json={"event_id": "NON_EXISTENT_EVENT"})
    assert resp.status_code == 404


def test_api_risk_high(setup_test_db):
    client = TestClient(app)
    client.post("/api/v1/risk/calculate", json={"event_id": "EVT000001"})
    resp = client.get("/api/v1/risk/high?min_score=50")
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data


def test_api_risk_summary(setup_test_db):
    client = TestClient(app)
    client.post("/api/v1/risk/calculate", json={"event_id": "EVT000001"})
    resp = client.get("/api/v1/risk/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_incidents"] >= 1
    assert "risk_distribution" in data
    assert "trend" in data


def test_api_incidents_crud_and_status(setup_test_db):
    client = TestClient(app)
    client.post("/api/v1/risk/calculate", json={"event_id": "EVT000001"})

    # 1. List incidents
    resp = client.get("/api/v1/incidents?limit=10")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    incident_id = data["items"][0]["incident_id"]

    # 2. Get single incident
    resp = client.get(f"/api/v1/incidents/{incident_id}")
    assert resp.status_code == 200
    inc = resp.json()
    assert inc["incident_id"] == incident_id

    # 3. Update status - test all 4 valid statuses
    for st in ["Investigating", "Resolved", "False Positive", "Open"]:
        patch_resp = client.patch(f"/api/v1/incidents/{incident_id}/status", json={"status": st})
        assert patch_resp.status_code == 200
        assert patch_resp.json()["status"] == st
        # Verify GET reflects updated status
        get_check = client.get(f"/api/v1/incidents/{incident_id}")
        assert get_check.status_code == 200
        assert get_check.json()["status"] == st

    # 4. Bad status returns 400
    bad_resp = client.patch(f"/api/v1/incidents/{incident_id}/status", json={"status": "InvalidStatus"})
    assert bad_resp.status_code == 400

    # 5. Non-existent incident returns 404
    missing_resp = client.patch("/api/v1/incidents/INC-NONEXISTENT/status", json={"status": "Investigating"})
    assert missing_resp.status_code == 404

    # 6. CORS preflight allows PATCH
    opt_resp = client.options(
        f"/api/v1/incidents/{incident_id}/status",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "PATCH",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert opt_resp.status_code == 200
    assert "PATCH" in opt_resp.headers.get("access-control-allow-methods", "")


def test_api_attack_chains(setup_test_db):
    client = TestClient(app)
    # Create incident with attack chain
    client.post("/api/v1/risk/calculate", json={"event_id": "EVT000001"})
    resp = client.get("/api/v1/attack-chains")
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data
    assert isinstance(data["items"], list)
    if data["items"]:
        item = data["items"][0]
        assert "attack_chain_id" in item
        assert "confidence" in item
        assert item["attack_chain_id"].startswith("AC-")


def test_api_recommendations(setup_test_db):
    client = TestClient(app)
    client.post("/api/v1/risk/calculate", json={"event_id": "EVT000001"})
    resp = client.get("/api/v1/recommendations/INC-000001")
    assert resp.status_code == 200
    data = resp.json()
    assert data["incident_id"] == "INC-000001"
    assert len(data["recommendations"]) > 0


def test_anchor_event_id_deduplication(setup_test_db):
    db = setup_test_db
    # Process EVT000001 twice
    inc1 = process_event_to_incident("EVT000001", db=db, persist=True)
    inc2 = process_event_to_incident("EVT000001", db=db, persist=True)
    
    assert inc1["incident_id"] == inc2["incident_id"]
    assert inc1["anchor_event_id"] == "EVT000001"
    
    # Ensure there is only 1 incident in DB
    assert db["incidents"].count_documents({}) == 1


def test_anchor_vs_correlated_deduplication(setup_test_db):
    db = setup_test_db
    # EVT000002 is correlated with EVT000001 (based on earlier tests)
    # 1. Process EVT000001 (EVT000002 gets sucked in as correlated)
    inc1 = process_event_to_incident("EVT000001", db=db, persist=True)
    assert "EVT000002" in inc1["event_ids"]
    assert inc1["anchor_event_id"] == "EVT000001"
    
    # 2. Process EVT000002 independently. Before the fix, this would return inc1.
    # After the fix, it creates its own incident anchored on EVT000002.
    inc2 = process_event_to_incident("EVT000002", db=db, persist=True)
    assert inc2["incident_id"] != inc1["incident_id"]
    assert inc2["anchor_event_id"] == "EVT000002"
    
    # Check that we now have 2 incidents in the DB
    assert db["incidents"].count_documents({}) == 2


# ── 7. Threat Intelligence Field Mapping Tests ────────────────────────────────

def test_threat_intel_source_ip_lookup(setup_test_db):
    """threat_actor must come from the DB threat_actor field, not confidence/severity."""
    from risk.enrichment import enrich_threat_intel
    event = {
        "source_ip": "192.0.2.1",
        "destination_ip": "10.9.9.9",
    }
    result = enrich_threat_intel(event)
    assert result.found is True
    assert result.threat_actor == "APT-Test-Group"       # From DB, not confidence
    assert result.threat_name == "Brute Force Campaign"  # Real campaign name
    assert result.confidence == "High"
    assert result.severity == "High"
    assert result.ioc_value == "192.0.2.1"
    assert result.ioc_matched_field == "source_ip"
    # Ensure threat_actor is NOT confidence or severity
    assert result.threat_actor != result.confidence
    assert result.threat_actor != result.severity


def test_threat_intel_destination_ip_fallback(setup_test_db):
    """When source_ip has no match, destination_ip should be used."""
    from risk.enrichment import enrich_threat_intel
    event = {
        "source_ip": "99.99.99.99",    # No match in threat_intel
        "destination_ip": "10.0.5.208",  # Has a match
    }
    result = enrich_threat_intel(event)
    assert result.found is True
    assert result.ioc_value == "10.0.5.208"
    assert result.threat_actor == "TA-Desttest"
    assert result.ioc_matched_field == "destination_ip"


def test_threat_intel_source_precedence_over_destination(setup_test_db):
    """When both source and destination IPs match, source_ip takes precedence."""
    from risk.enrichment import enrich_threat_intel
    event = {
        "source_ip": "192.0.2.1",      # Has a match
        "destination_ip": "10.0.5.208",  # Also has a match
    }
    result = enrich_threat_intel(event)
    assert result.found is True
    assert result.ioc_value == "192.0.2.1"       # source_ip takes precedence
    assert result.ioc_matched_field == "source_ip"
    assert result.threat_actor == "APT-Test-Group"


def test_threat_intel_no_match(setup_test_db):
    """If no match for source or destination IP, enrichment is not found."""
    from risk.enrichment import enrich_threat_intel
    event = {
        "source_ip": "1.2.3.4",
        "destination_ip": "5.6.7.8",
    }
    result = enrich_threat_intel(event)
    assert result.found is False
    assert result.threat_actor is None


def test_incident_threat_intel_fields_correct(setup_test_db):
    """Incident document must have correct threat intel fields from DB, not derived values."""
    db = setup_test_db
    incident = process_event_to_incident("EVT000001", db=db, persist=True)
    assert incident["ioc_status"] == "Malicious"
    # threat_actor must not be "High" or "Critical" (which would be confidence/severity values)
    threat_actor = incident.get("threat_actor")
    assert threat_actor != "High"
    assert threat_actor != "Critical"
    assert threat_actor != "Low"
    assert threat_actor != "Medium"
    # threat_actor should be the actual value from the DB
    assert threat_actor == "APT-Test-Group"
    # threat_name should be the campaign name
    assert incident.get("threat_name") == "Brute Force Campaign"


# ── 8. Date Range Filter Tests ────────────────────────────────────────────────

def test_date_range_end_date_includes_full_day(setup_test_db):
    """Selecting end_date=2025-08-03 must include events at any time on Aug 3."""
    from fastapi.testclient import TestClient
    from main import app
    client = TestClient(app)
    # Create incident
    client.post("/api/v1/risk/calculate", json={"event_id": "EVT000001"})
    # Filter with end_date only
    resp = client.get("/api/v1/incidents?end_date=2025-08-03")
    assert resp.status_code == 200
    data = resp.json()
    # Event EVT000001 has timestamp 2025-08-03 08:10:00 — must be included
    assert data["total"] >= 1


def test_date_range_end_date_excludes_outside(setup_test_db):
    """Events after end_date should be excluded."""
    from fastapi.testclient import TestClient
    from main import app
    client = TestClient(app)
    client.post("/api/v1/risk/calculate", json={"event_id": "EVT000001"})
    # End date before event date — should exclude
    resp = client.get("/api/v1/incidents?end_date=2025-07-01")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0


def test_date_range_start_date_only(setup_test_db):
    """Start date only: events on or after start_date should be included."""
    from fastapi.testclient import TestClient
    from main import app
    client = TestClient(app)
    client.post("/api/v1/risk/calculate", json={"event_id": "EVT000001"})
    resp = client.get("/api/v1/incidents?start_date=2025-08-01")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1


def test_date_range_start_and_end(setup_test_db):
    """Start + end range: Aug 1 - Aug 31 includes Aug 3 event."""
    from fastapi.testclient import TestClient
    from main import app
    client = TestClient(app)
    client.post("/api/v1/risk/calculate", json={"event_id": "EVT000001"})
    resp = client.get("/api/v1/incidents?start_date=2025-08-01&end_date=2025-08-31")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1


# ── Feature 1: Dynamic Risk Weights Tests ────────────────────────────────────

def test_dynamic_risk_weights_lifecycle(setup_test_db):
    """Test GET, PUT (valid & invalid), and POST reset for dynamic risk weights."""
    from fastapi.testclient import TestClient
    from main import app
    client = TestClient(app)

    # 1. GET default weights
    resp = client.get("/api/v1/risk/weights")
    assert resp.status_code == 200
    w = resp.json()
    assert w["threat_severity"] == 0.25
    assert w["ml_confidence"] == 0.25
    assert w["asset_criticality"] == 0.20
    assert w["vulnerability_cvss"] == 0.20
    assert w["threat_intelligence"] == 0.10

    # 2. PUT valid weights (sum = 1.0)
    valid_payload = {
        "threat_severity": 0.30,
        "ml_confidence": 0.20,
        "asset_criticality": 0.25,
        "vulnerability_cvss": 0.15,
        "threat_intelligence": 0.10,
    }
    resp_put = client.put("/api/v1/risk/weights", json=valid_payload)
    assert resp_put.status_code == 200
    w_updated = resp_put.json()
    assert w_updated["threat_severity"] == 0.30
    assert w_updated["ml_confidence"] == 0.20

    # Verify calculation uses updated weights
    calc_resp = client.post("/api/v1/risk/calculate", json={"event_id": "EVT000001"})
    assert calc_resp.status_code == 200
    breakdown_factors = calc_resp.json()["risk_breakdown"]["factors"]
    factor_map = {f["name"]: f["weight"] for f in breakdown_factors}
    assert factor_map["ThreatSeverity"] == 0.30
    assert factor_map["MLConfidence"] == 0.20

    # 3. PUT invalid weights (sum = 0.90 != 1.0)
    invalid_sum = {
        "threat_severity": 0.20,
        "ml_confidence": 0.20,
        "asset_criticality": 0.20,
        "vulnerability_cvss": 0.20,
        "threat_intelligence": 0.10,
    }
    resp_bad = client.put("/api/v1/risk/weights", json=invalid_sum)
    assert resp_bad.status_code == 400
    assert "must sum to exactly 1.0" in resp_bad.json()["detail"]

    # 4. PUT invalid negative weight
    invalid_neg = {
        "threat_severity": -0.10,
        "ml_confidence": 0.40,
        "asset_criticality": 0.30,
        "vulnerability_cvss": 0.20,
        "threat_intelligence": 0.20,
    }
    resp_neg = client.put("/api/v1/risk/weights", json=invalid_neg)
    assert resp_neg.status_code == 422 or resp_neg.status_code == 400

    # 5. POST reset
    resp_reset = client.post("/api/v1/risk/weights/reset")
    assert resp_reset.status_code == 200
    w_reset = resp_reset.json()
    assert w_reset["threat_severity"] == 0.25
    assert w_reset["ml_confidence"] == 0.25


# ── Feature 3: Risk Score Comparison Tests ───────────────────────────────────

def test_risk_score_comparison_in_incident(setup_test_db):
    """Test that incident details include explainable risk_score_comparison."""
    from fastapi.testclient import TestClient
    from main import app
    client = TestClient(app)

    # Trigger creation
    calc_resp = client.post("/api/v1/risk/calculate", json={"event_id": "EVT000001"})
    assert calc_resp.status_code == 200
    assert "risk_score_comparison" in calc_resp.json()
    comp = calc_resp.json()["risk_score_comparison"]
    assert comp["before_correlation"] == comp["after_correlation"]
    assert comp["change"] == 0
    assert "Correlation increased investigation context" in comp["change_reason"]

    # Fetch incident by ID
    inc_resp = client.get("/api/v1/incidents/INC-000001")
    assert inc_resp.status_code == 200
    inc_data = inc_resp.json()
    assert "risk_score_comparison" in inc_data
    assert inc_data["risk_score_comparison"]["before_correlation"] == inc_data["risk_score"]
    assert inc_data["risk_score_comparison"]["change"] == 0


# ── Feature 4: Analyst Feedback Loop Tests ────────────────────────────────────

def test_analyst_feedback_submission_and_retrieval(setup_test_db):
    """Test submitting structured False Positive feedback and retrieving history."""
    from fastapi.testclient import TestClient
    from main import app
    client = TestClient(app)

    # Ensure incident exists
    client.post("/api/v1/risk/calculate", json={"event_id": "EVT000001"})

    # 1. Submit valid False Positive feedback
    fb_payload = {
        "reason": "Security scanner / automated tool",
        "comment": "Verified internal Qualys vulnerability scan.",
        "analyst": "analyst.alice@corp.local",
    }
    fb_resp = client.post("/api/v1/incidents/INC-000001/feedback", json=fb_payload)
    assert fb_resp.status_code == 200
    fb_data = fb_resp.json()
    assert fb_data["reason"] == "Security scanner / automated tool"
    assert fb_data["resulting_status"] == "False Positive"
    assert fb_data["incident_id"] == "INC-000001"
    assert fb_data["analyst"] == "analyst.alice@corp.local"

    # Verify incident status is updated to False Positive
    inc_resp = client.get("/api/v1/incidents/INC-000001")
    assert inc_resp.status_code == 200
    assert inc_resp.json()["status"] == "False Positive"
    assert len(inc_resp.json()["feedback"]) >= 1

    # 2. Retrieve feedback history
    history_resp = client.get("/api/v1/incidents/INC-000001/feedback")
    assert history_resp.status_code == 200
    history = history_resp.json()
    assert len(history) >= 1
    assert history[0]["reason"] == "Security scanner / automated tool"

    # 3. Submit invalid feedback reason -> 400
    bad_payload = {
        "reason": "Not a valid reason text",
        "comment": "Bad reason",
    }
    bad_resp = client.post("/api/v1/incidents/INC-000001/feedback", json=bad_payload)
    assert bad_resp.status_code == 400
    assert "Invalid feedback reason" in bad_resp.json()["detail"]


# ── Final Hardening & Completeness Regression Tests ──────────────────────────

def test_dynamic_risk_weights_with_zero_factor(setup_test_db):
    """Test dynamic risk weights configured with a 0% factor weight."""
    from fastapi.testclient import TestClient
    from main import app
    client = TestClient(app)

    # 1. Update weights with threat_severity = 0.0 (and others summing to 1.0)
    zero_threat_weights = {
        "threat_severity": 0.0,
        "ml_confidence": 0.35,
        "asset_criticality": 0.25,
        "vulnerability_cvss": 0.25,
        "threat_intelligence": 0.15,
    }
    resp = client.put("/api/v1/risk/weights", json=zero_threat_weights)
    assert resp.status_code == 200
    saved = resp.json()
    assert saved["threat_severity"] == 0.0
    assert saved["ml_confidence"] == 0.35

    # 2. Verify GET returns exact 0.0 without defaulting back to 0.25
    get_resp = client.get("/api/v1/risk/weights")
    assert get_resp.status_code == 200
    current = get_resp.json()
    assert current["threat_severity"] == 0.0

    # 3. Calculate risk with zero threat weight
    calc_resp = client.post("/api/v1/risk/calculate", json={"event_id": "EVT000001"})
    assert calc_resp.status_code == 200
    breakdown = calc_resp.json()["risk_breakdown"]["factors"]
    sev_factor = next(f for f in breakdown if f["name"] == "ThreatSeverity")
    assert sev_factor["weight"] == 0.0
    assert sev_factor["contribution"] == 0.0

    # 4. Reset back to defaults and verify
    reset_resp = client.post("/api/v1/risk/weights/reset")
    assert reset_resp.status_code == 200
    assert reset_resp.json()["threat_severity"] == 0.25


def test_threat_intel_ioc_propagation_and_fallback(setup_test_db):
    """
    Test threat intelligence enrichment:
    - Source IP match precedence
    - Destination IP fallback
    - Clean / no-match state
    - Complete field propagation to incident document
    """
    from fastapi.testclient import TestClient
    from main import app
    from risk.enrichment import enrich_threat_intel
    client = TestClient(app)

    # 1. Source IP match test (EVT000001 source_ip = 192.0.2.1)
    evt_source = {
        "event_id": "EVT-TEST-SRC",
        "source_ip": "192.0.2.1",
        "destination_ip": "10.0.5.208", # Both match, source has precedence
    }
    ti_src = enrich_threat_intel(evt_source)
    assert ti_src.found is True
    assert ti_src.ioc_value == "192.0.2.1"
    assert ti_src.ioc_matched_field == "source_ip"
    assert ti_src.threat_name == "Brute Force Campaign"
    assert ti_src.threat_actor == "APT-Test-Group"
    assert ti_src.confidence == "High"
    assert ti_src.severity == "High"

    # 2. Destination IP fallback test (source doesn't match, destination does)
    evt_dest = {
        "event_id": "EVT-TEST-DST",
        "source_ip": "172.16.1.50",     # No match in TI
        "destination_ip": "10.0.5.208", # Matches in TI
    }
    ti_dst = enrich_threat_intel(evt_dest)
    assert ti_dst.found is True
    assert ti_dst.ioc_value == "10.0.5.208"
    assert ti_dst.ioc_matched_field == "destination_ip"
    assert ti_dst.threat_name == "C2 Callback Campaign"
    assert ti_dst.threat_actor == "TA-Desttest"
    assert ti_dst.confidence == "Medium"

    # 3. Clean event (no TI match)
    evt_clean = {
        "event_id": "EVT-TEST-CLN",
        "source_ip": "172.16.1.50",
        "destination_ip": "172.16.1.60",
    }
    ti_cln = enrich_threat_intel(evt_clean)
    assert ti_cln.found is False
    assert ti_cln.ioc_value is None
    assert ti_cln.ioc_matched_field is None

    # 4. End-to-end incident document verification via API
    client.post("/api/v1/risk/calculate", json={"event_id": "EVT000001"})
    inc_resp = client.get("/api/v1/incidents/INC-000001")
    assert inc_resp.status_code == 200
    inc = inc_resp.json()
    assert inc["ioc_status"] == "Malicious"
    assert inc["ioc_value"] == "192.0.2.1"
    assert inc["ioc_matched_field"] == "source_ip"
    assert inc["threat_name"] == "Brute Force Campaign"
    assert inc["threat_actor"] == "APT-Test-Group"
    assert inc["ioc_type"] == "IP Address"


def test_incident_status_history_audit_trail(setup_test_db):
    """
    Test that incident status history tracks lifecycle transitions:
    - Initial 'Open' entry on creation
    - PATCH status updates record changed_by, changed_at, reason
    - Feedback submission adds False Positive audit entry
    """
    from fastapi.testclient import TestClient
    from main import app
    client = TestClient(app)

    # 1. Trigger incident creation
    client.post("/api/v1/risk/calculate", json={"event_id": "EVT000001"})
    inc = client.get("/api/v1/incidents/INC-000001").json()

    assert "status_history" in inc
    assert len(inc["status_history"]) >= 1
    assert inc["status_history"][0]["status"] == "Open"
    assert inc["status_history"][0]["changed_by"] == "System"

    # 2. Update status to Investigating
    patch_resp = client.patch(
        "/api/v1/incidents/INC-000001/status",
        json={"status": "Investigating", "changed_by": "lead.analyst@corp.local", "reason": "Triage started"}
    )
    assert patch_resp.status_code == 200
    updated_inc = patch_resp.json()
    assert updated_inc["status"] == "Investigating"
    assert len(updated_inc["status_history"]) >= 2
    last_entry = updated_inc["status_history"][-1]
    assert last_entry["status"] == "Investigating"
    assert last_entry["changed_by"] == "lead.analyst@corp.local"
    assert last_entry["reason"] == "Triage started"

    # 3. Submit False Positive feedback
    fb_resp = client.post(
        "/api/v1/incidents/INC-000001/feedback",
        json={
            "reason": "Expected user behavior",
            "comment": "Scheduled administrative batch job.",
            "analyst": "analyst.bob@corp.local",
        }
    )
    assert fb_resp.status_code == 200

    # 4. Fetch incident again and verify audit history reflects the feedback
    final_inc = client.get("/api/v1/incidents/INC-000001").json()
    assert final_inc["status"] == "False Positive"
    assert len(final_inc["status_history"]) >= 3
    fp_entry = final_inc["status_history"][-1]
    assert fp_entry["status"] == "False Positive"
    assert fp_entry["changed_by"] == "analyst.bob@corp.local"
    assert fp_entry["reason"] == "Expected user behavior"

