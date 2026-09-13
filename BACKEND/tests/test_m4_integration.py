"""
tests/test_m4_integration.py — Milestone 4 Comprehensive Test Suite
====================================================================
Milestone 4: Backend Final Integration, API Completion & Production Hardening

Tests cover:
  1. Dashboard Overview Aggregation (GET /api/v1/dashboard/overview)
  2. Relative Time Window Filtering (24h, 7d, 30d, all, custom date range)
  3. Deterministic Security Posture Engine (GET /api/v1/dashboard/security-posture)
  4. IOC Intelligence Aggregation (GET /api/v1/threat-intel/indicators & summary)
  5. Vulnerability Intelligence Aggregation (GET /api/v1/vulnerabilities/summary & query)
  6. Combined Cross-Domain Filtering on Incidents (Severity, Asset, CVE, IOC status)
  7. End-to-End Investigation Drill-Down (Overview -> Incident -> Event)
  8. Executive Security Briefing Summary (GET /api/v1/executive/summary)
  9. Automated Security Reporting (GET /api/v1/reports/security & security.csv)
  10. Incident Lifecycle & Audit Trail Regression
  11. Semantic Analyst Feedback Regression (Capture & Global Audit)
  12. Milestone 1, 2, and 3 Endpoint Regressions
"""

import os
import sys
from datetime import datetime, timezone

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import mongomock
import pytest
from fastapi.testclient import TestClient

from database.incident_repository import ensure_incident_indexes
from database.mongo_db import MongoDatabase
from main import app
from services.data_store import store


def _setup_m4_mock_db():
    """Create isolated mock MongoDB environment with comprehensive M1-M4 test data."""
    mock_client = mongomock.MongoClient()
    mock_db = mock_client["threat_detection"]

    # 1. Assets
    mock_db["assets"].insert_many([
        {"asset_id": "AST001", "asset_name": "WebServer", "criticality": "Critical", "department": "IT"},
        {"asset_id": "AST002", "asset_name": "Database-01", "criticality": "Critical", "department": "IT"},
        {"asset_id": "AST003", "asset_name": "Finance-PC-02", "criticality": "High", "department": "Finance"},
        {"asset_id": "AST004", "asset_name": "HR-PC-01", "criticality": "Medium", "department": "HR"},
    ])

    # 2. Vulnerabilities
    mock_db["vulnerabilities"].insert_many([
        {
            "vulnerability_id": "VUL001",
            "cve_id": "CVE-2024-1045",
            "vulnerability_name": "Privilege Escalation Flaw",
            "severity": "Critical",
            "cvss_score": 9.5,
            "affected_asset": "Database-01",
            "patch_available": "Yes",
            "status": "Open",
        },
        {
            "vulnerability_id": "VUL002",
            "cve_id": "CVE-2023-1234",
            "vulnerability_name": "Improper Input Validation",
            "severity": "High",
            "cvss_score": 8.4,
            "affected_asset": "WebServer",
            "patch_available": "Yes",
            "status": "Open",
        },
        {
            "vulnerability_id": "VUL003",
            "cve_id": "CVE-2024-2201",
            "vulnerability_name": "Information Disclosure",
            "severity": "Medium",
            "cvss_score": 5.9,
            "affected_asset": "Finance-PC-02",
            "patch_available": "No",
            "status": "Closed",
        },
    ])

    # 3. Static MITRE mapping
    mock_db["mitre_attack_mapping"].insert_many([
        {"event_type": "Brute Force", "mitre_id": "T1110", "technique_id": "T1110", "technique_name": "Brute Force", "tactic": "Credential Access"},
        {"event_type": "Privilege Escalation", "mitre_id": "T1068", "technique_id": "T1068", "technique_name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
        {"event_type": "SQL Injection Attempt", "mitre_id": "T1190", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        {"event_type": "Failed Login", "mitre_id": "T1078", "technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Defense Evasion"},
        {"event_type": "Login Success", "mitre_id": "T1078", "technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Defense Evasion"},
    ])

    # 4. Threat Intelligence
    mock_db["threat_intelligence"].insert_many([
        {
            "indicator_id": "IOC001",
            "indicator_type": "IP Address",
            "indicator_value": "192.0.2.1",
            "threat_name": "Brute Force Campaign",
            "threat_actor": "APT-Test-Group",
            "confidence": "High",
            "severity": "High",
        },
        {
            "indicator_id": "IOC002",
            "indicator_type": "IP Address",
            "indicator_value": "198.51.100.1",
            "threat_name": "Malware Distribution Network",
            "threat_actor": "Unknown",
            "confidence": "Critical",
            "severity": "Critical",
        },
    ])

    # 5. Security Events across multiple timestamps (for time-range testing)
    mock_db["security_events"].insert_many([
        {
            "event_id": "EVT000001",
            "timestamp": "2025-08-07 05:00:00",
            "source_ip": "192.0.2.1",
            "destination_ip": "10.0.5.208",
            "event_type": "Brute Force",
            "username": "admin",
            "severity": "High",
            "event_status": "Failed",
            "asset_name": "Database-01",
            "department": "IT",
            "vulnerability_id": "CVE-2024-1045",
        },
        {
            "event_id": "EVT000002",
            "timestamp": "2025-08-07 04:30:00",
            "source_ip": "192.0.2.1",
            "destination_ip": "10.0.5.208",
            "event_type": "Privilege Escalation",
            "username": "admin",
            "severity": "Critical",
            "event_status": "Open",
            "asset_name": "Database-01",
            "department": "IT",
            "vulnerability_id": "CVE-2024-1045",
        },
        {
            "event_id": "EVT000003",
            "timestamp": "2025-08-05 12:00:00",
            "source_ip": "198.51.100.1",
            "destination_ip": "10.0.2.15",
            "event_type": "SQL Injection Attempt",
            "username": "guest",
            "severity": "Critical",
            "event_status": "Blocked",
            "asset_name": "WebServer",
            "department": "IT",
            "vulnerability_id": "CVE-2023-1234",
        },
        {
            "event_id": "EVT000004",
            "timestamp": "2025-08-01 10:00:00",
            "source_ip": "10.0.1.5",
            "destination_ip": "10.0.1.20",
            "event_type": "Failed Login",
            "username": "alice",
            "severity": "Low",
            "event_status": "Failed",
            "asset_name": "HR-PC-01",
            "department": "HR",
        },
    ])

    # 6. Incidents collection
    mock_db["incidents"].insert_many([
        {
            "incident_id": "INC-000001",
            "anchor_event_id": "EVT000001",
            "event_ids": ["EVT000001", "EVT000002"],
            "threat_type": "Brute Force",
            "risk_score": 85,
            "risk_level": "Critical",
            "priority": "CRITICAL_IMMEDIATE",
            "asset_name": "Database-01",
            "department": "IT",
            "affected_user": "admin",
            "ml_confidence": 92.0,
            "anomaly_score": 88.0,
            "source_ip": "192.0.2.1",
            "destination_ip": "10.0.5.208",
            "severity": "High",
            "cve_id": "CVE-2024-1045",
            "ioc_status": "Malicious",
            "mitre_techniques": ["T1110"],
            "related_events_count": 1,
            "attack_chain_detected": True,
            "attack_chain_type": "Brute Force Chain",
            "attack_chain": {
                "attack_chain_id": "AC-INC-000001",
                "attack_chain_detected": True,
                "attack_chain_type": "Brute Force Chain",
                "confidence": "High",
            },
            "risk_breakdown": {
                "factors": [
                    {"name": "Threat Severity", "value": 75, "weight": 0.25, "contribution": 18.8, "reason": "High severity"},
                    {"name": "ML Confidence", "value": 92, "weight": 0.25, "contribution": 23.0, "reason": "High ML confidence"},
                    {"name": "Asset Criticality", "value": 100, "weight": 0.20, "contribution": 20.0, "reason": "Critical asset"},
                    {"name": "Vulnerability CVSS", "value": 95, "weight": 0.20, "contribution": 19.0, "reason": "Critical CVE"},
                    {"name": "Threat Intelligence", "value": 80, "weight": 0.10, "contribution": 8.0, "reason": "Active IOC"},
                ]
            },
            "recommendations": [
                {"action": "Isolate Endpoint", "reason": "Active brute force attack detected", "priority": "CRITICAL"}
            ],
            "status": "Open",
            "created_at": "2025-08-07 05:00:00",
            "status_history": [
                {"status": "Open", "changed_by": "System", "changed_at": "2025-08-07 05:00:00", "reason": "Incident initialized"}
            ],
        },
        {
            "incident_id": "INC-000002",
            "anchor_event_id": "EVT000003",
            "event_ids": ["EVT000003"],
            "threat_type": "SQL Injection Attempt",
            "risk_score": 75,
            "risk_level": "High",
            "priority": "HIGH_IMMEDIATE",
            "asset_name": "WebServer",
            "department": "IT",
            "affected_user": "guest",
            "ml_confidence": 88.0,
            "anomaly_score": 70.0,
            "source_ip": "198.51.100.1",
            "destination_ip": "10.0.2.15",
            "severity": "Critical",
            "cve_id": "CVE-2023-1234",
            "ioc_status": "Malicious",
            "mitre_techniques": ["T1190"],
            "related_events_count": 0,
            "attack_chain_detected": False,
            "risk_breakdown": {
                "factors": [
                    {"name": "Threat Severity", "value": 100, "weight": 0.25, "contribution": 25.0, "reason": "Critical severity"},
                    {"name": "ML Confidence", "value": 88, "weight": 0.25, "contribution": 22.0, "reason": "High ML confidence"},
                    {"name": "Asset Criticality", "value": 100, "weight": 0.20, "contribution": 20.0, "reason": "Critical asset"},
                    {"name": "Vulnerability CVSS", "value": 84, "weight": 0.20, "contribution": 16.8, "reason": "High CVE"},
                    {"name": "Threat Intelligence", "value": 100, "weight": 0.10, "contribution": 10.0, "reason": "Critical IOC"},
                ]
            },
            "recommendations": [
                {"action": "Deploy WAF Rule", "reason": "SQL injection attempts on public endpoint", "priority": "HIGH"}
            ],
            "status": "Open",
            "created_at": "2025-08-05 12:00:00",
            "status_history": [
                {"status": "Open", "changed_by": "System", "changed_at": "2025-08-05 12:00:00", "reason": "Incident initialized"}
            ],
        },
    ])

    # 7. M2 Predictions
    mock_db["threat_predictions"].insert_many([
        {
            "prediction_id": "PRED_001",
            "event_id": "EVT000001",
            "prediction_timestamp": "2025-08-07 05:00:00",
            "verdict": "Critical",
            "confidence_score": 92.0,
            "predicted_threat_type": "Brute Force",
            "rf_top_probability": 0.92,
            "rf_confidence_note": "high",
            "anomaly_label": "Anomaly",
            "anomaly_score": 88.0,
            "anomaly_score_raw": -0.75,
            "rule_score": 80.0,
            "triggered_rules": ["RULE_HIGH_SEVERITY"],
            "reasons": [],
            "model_signals": {"if_anomaly_normalized": 88.0, "rf_score_normalized": 92.0, "rule_score": 80.0},
        }
    ])

    # Patch global MongoDB singleton
    mongo_instance = MongoDatabase()
    mongo_instance.client = mock_client
    mongo_instance.db = mock_db
    mongo_instance._connected = True

    from database import mongo_db
    mongo_db.mongo = mongo_instance

    import services.data_store
    services.data_store.mongo = mongo_instance

    import database.prediction_store
    database.prediction_store.mongo = mongo_instance

    store._loaded = False
    store.load()
    ensure_incident_indexes(mock_db)

    return mock_db


@pytest.fixture(autouse=True)
def setup_test_environment():
    return _setup_m4_mock_db()


# ── Test 1: Dashboard Overview Aggregation ────────────────────────────────────

def test_dashboard_overview_aggregation():
    client = TestClient(app)
    res = client.get("/api/v1/dashboard/overview?time_range=all")
    assert res.status_code == 200
    data = res.json()

    assert data["total_security_events"] == 4
    assert data["detected_threats"] == 3   # EVT001 (High), EVT002 (Critical), EVT003 (Critical)
    assert data["critical_threats"] == 2
    assert data["high_risk_incidents"] == 2  # INC-001 (85), INC-002 (75)
    assert data["active_incidents"] == 2
    assert data["affected_assets"] >= 2

    # Severity distribution
    sev_dist = data["threat_severity_distribution"]
    assert sev_dist["Critical"] == 2
    assert sev_dist["High"] == 1
    assert sev_dist["Low"] == 1

    # Status distribution
    status_dist = data["incident_status_distribution"]
    assert status_dist["Open"] == 2
    assert status_dist["Resolved"] == 0

    # Posture included
    posture = data["security_posture"]
    assert "posture_score" in posture
    assert 0 <= posture["posture_score"] <= 100


# ── Test 2: Time Range Filtering (24h, 7d, 30d, custom dates) ─────────────────

def test_time_range_filtering():
    client = TestClient(app)

    # 24h filter: anchored to latest event (2025-08-07 05:00:00), window is 2025-08-06 to 2025-08-07
    res_24h = client.get("/api/v1/dashboard/overview?time_range=24h")
    assert res_24h.status_code == 200
    d_24h = res_24h.json()
    assert d_24h["total_security_events"] == 2  # EVT001 and EVT002
    assert d_24h["high_risk_incidents"] == 1    # Only INC-000001 (Aug 7)

    # 7d filter: covers all events from Aug 1 to Aug 7
    res_7d = client.get("/api/v1/dashboard/overview?time_range=7d")
    assert res_7d.status_code == 200
    d_7d = res_7d.json()
    assert d_7d["total_security_events"] == 4

    # Custom date range
    res_custom = client.get("/api/v1/dashboard/overview?start_date=2025-08-04&end_date=2025-08-06")
    assert res_custom.status_code == 200
    d_cust = res_custom.json()
    assert d_cust["total_security_events"] == 1  # EVT000003 on Aug 5


# ── Test 3: Deterministic Security Posture Calculation ────────────────────────

def test_security_posture_calculation():
    client = TestClient(app)
    res = client.get("/api/v1/dashboard/security-posture")
    assert res.status_code == 200
    data = res.json()

    assert "posture_score" in data
    assert isinstance(data["posture_score"], int)
    assert 0 <= data["posture_score"] <= 100
    assert data["posture_label"] in ["Excellent", "Good", "Needs Attention", "Critical"]
    assert data["baseline"] == 100.0
    assert data["total_deduction"] > 0

    factors = data["contributing_factors"]
    assert "active_incidents" in factors
    assert "critical_vulnerabilities" in factors
    assert "asset_exposure" in factors
    assert "unresolved_threats" in factors
    assert "threat_volume" in factors

    assert len(data["calculation_explanation"]) > 20


# ── Test 4: IOC Intelligence Aggregation ──────────────────────────────────────

def test_ioc_intelligence_aggregation():
    client = TestClient(app)

    # Feed
    res = client.get("/api/v1/threat-intel/indicators")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 2
    assert len(data["items"]) == 2

    # Check correlated metrics for 192.0.2.1 (which matched EVT001 & EVT002)
    ioc_item = next(i for i in data["items"] if i["indicator_value"] == "192.0.2.1")
    assert ioc_item["threat_count"] == 2
    assert ioc_item["affected_asset_count"] == 1
    assert "Database-01" in ioc_item["affected_assets"]
    assert ioc_item["first_seen"] == "2025-08-07 04:30:00"
    assert ioc_item["last_seen"] == "2025-08-07 05:00:00"
    assert ioc_item["malicious_status"] == "Malicious"

    # Search filter
    res_search = client.get("/api/v1/threat-intel/indicators?search=198.51.100.1")
    assert res_search.status_code == 200
    assert res_search.json()["total"] == 1

    # Status filter
    res_mal = client.get("/api/v1/threat-intel/indicators?status=Malicious")
    assert res_mal.status_code == 200
    assert res_mal.json()["total"] == 2
    assert all(item["malicious_status"] == "Malicious" for item in res_mal.json()["items"])

    res_ben = client.get("/api/v1/threat-intel/indicators?status=Benign")
    assert res_ben.status_code == 200
    assert res_ben.json()["total"] == 0

    # Summary
    res_sum = client.get("/api/v1/threat-intel/summary")
    assert res_sum.status_code == 200
    s_data = res_sum.json()
    assert s_data["total_indicators"] == 2
    assert s_data["malicious_indicators"] == 2


# ── Test 5: Vulnerability Intelligence Aggregation ────────────────────────────

def test_vulnerability_intelligence_aggregation():
    client = TestClient(app)

    # Summary
    res_sum = client.get("/api/v1/vulnerabilities/summary")
    assert res_sum.status_code == 200
    s_data = res_sum.json()
    assert s_data["total_vulnerabilities"] == 3
    assert s_data["critical_cves"] == 1
    assert s_data["high_cves"] == 1
    assert s_data["medium_cves"] == 1
    assert s_data["status_distribution"]["Open"] == 2
    assert s_data["status_distribution"]["Closed"] == 1
    assert s_data["patch_availability"]["Yes"] == 2

    # Advanced filtered query
    res_filter = client.get("/api/v1/vulnerabilities?severity=Critical&status=Open")
    assert res_filter.status_code == 200
    f_data = res_filter.json()
    assert f_data["total"] == 1
    assert f_data["items"][0]["cve_id"] == "CVE-2024-1045"


# ── Test 6: Combined Cross-Domain Filtering on Incidents ───────────────────────

def test_combined_cross_domain_filtering():
    client = TestClient(app)

    # 1. Critical risk_level + IT department
    res1 = client.get("/api/v1/incidents?risk_level=Critical&department=IT")
    assert res1.status_code == 200
    d1 = res1.json()
    assert d1["total"] == 1
    assert d1["items"][0]["incident_id"] == "INC-000001"

    # 2. Asset name + CVE filter
    res2 = client.get("/api/v1/incidents?asset_name=WebServer&cve=CVE-2023-1234")
    assert res2.status_code == 200
    d2 = res2.json()
    assert d2["total"] == 1
    assert d2["items"][0]["incident_id"] == "INC-000002"

    # 3. Non-matching combination returns 0 items
    res3 = client.get("/api/v1/incidents?asset_name=HR-PC-01&risk_level=Critical")
    assert res3.status_code == 200
    assert res3.json()["total"] == 0


# ── Test 7: End-to-End Investigation Drill-Down ───────────────────────────────

def test_investigation_drill_down():
    client = TestClient(app)

    # 1. Overview -> Discover High-Risk Incidents
    res_ov = client.get("/api/v1/dashboard/overview")
    assert res_ov.status_code == 200

    # 2. Incident List
    res_inc = client.get("/api/v1/incidents?risk_level=Critical")
    assert res_inc.status_code == 200
    inc_id = res_inc.json()["items"][0]["incident_id"]

    # 3. Incident Details -> Hydrated Drill-Down Fields
    res_detail = client.get(f"/api/v1/incidents/{inc_id}")
    assert res_detail.status_code == 200
    d_inc = res_detail.json()
    assert d_inc["source_ip"] == "192.0.2.1"
    assert d_inc["destination_ip"] == "10.0.5.208"
    assert d_inc["cve_id"] == "CVE-2024-1045"
    assert d_inc["attack_chain_detected"] is True
    assert "related_events" in d_inc
    assert len(d_inc["related_events"]) == 2

    # 4. Individual Event Drill-Down (GET /events/{event_id})
    res_evt = client.get("/events/EVT000001")
    assert res_evt.status_code == 200
    d_evt = res_evt.json()
    assert d_evt["id"] == "EVT000001"
    assert d_evt["eventType"] == "Brute Force"
    assert d_evt["mitre"]["id"] == "T1110"


# ── Test 8: Executive Summary API ─────────────────────────────────────────────

def test_executive_summary():
    client = TestClient(app)
    res = client.get("/api/v1/executive/summary")
    assert res.status_code == 200
    data = res.json()

    assert "report_date" in data
    assert "security_posture" in data
    assert data["open_incidents"] == 2
    assert data["critical_vulnerabilities"] == 1
    assert data["affected_assets"] >= 2
    assert len(data["risk_distribution"]) == 5
    assert len(data["top_threat_categories"]) > 0


# ── Test 9: Automated Security Report Generation ──────────────────────────────

def test_security_report_generation():
    client = TestClient(app)

    # JSON report
    res_json = client.get("/api/v1/reports/security")
    assert res_json.status_code == 200
    data = res_json.json()
    assert "Creation of Security Operations Dashboard" in data["report_title"]
    assert data["total_events"] == 4
    assert "critical_vulnerabilities" in data
    assert data["critical_vulnerabilities"] >= 1
    assert "total_attack_chains" in data
    assert data["total_attack_chains"] >= 1
    assert len(data["top_threats"]) > 0
    assert len(data["top_vulnerabilities"]) > 0
    assert len(data["attack_chains"]) > 0

    # CSV report
    res_csv = client.get("/api/v1/reports/security.csv")
    assert res_csv.status_code == 200
    assert "text/csv" in res_csv.headers["content-type"]
    assert "attachment" in res_csv.headers["content-disposition"]
    csv_text = res_csv.text
    assert "SECURITY OPERATIONS DASHBOARD" in csv_text
    assert "Total Security Events,4" in csv_text
    assert "Critical Vulnerabilities" in csv_text
    assert "Total Attack Chains Detected" in csv_text


# ── Test 10: Incident Status Lifecycle Regression ─────────────────────────────

def test_incident_status_lifecycle_regression():
    client = TestClient(app)

    # 1. Update Open -> Investigating
    res1 = client.patch("/api/v1/incidents/INC-000001/status", json={"status": "Investigating", "reason": "Analyst triage"})
    assert res1.status_code == 200
    d1 = res1.json()
    assert d1["status"] == "Investigating"
    assert any(h["status"] == "Investigating" for h in d1["status_history"])

    # 2. Update Investigating -> Resolved
    res2 = client.patch("/api/v1/incidents/INC-000001/status", json={"status": "Resolved", "reason": "Threat neutralized"})
    assert res2.status_code == 200
    d2 = res2.json()
    assert d2["status"] == "Resolved"

    # 3. Invalid status returns 400
    res3 = client.patch("/api/v1/incidents/INC-000001/status", json={"status": "InvalidStatus"})
    assert res3.status_code == 400


# ── Test 11: Semantic Analyst Feedback Regression ─────────────────────────────

def test_analyst_feedback_semantic():
    client = TestClient(app)

    # Submit feedback with semantic fields
    fb_payload = {
        "reason": "Security scanner / automated tool",
        "comment": "Verified Nessus network scan.",
        "analyst": "Lead SOC Analyst",
        "event_id": "EVT000002",
        "prediction": "SQL Injection Attempt",
        "actual_feedback": "Automated security scanner probe",
    }
    res = client.post("/api/v1/incidents/INC-000002/feedback", json=fb_payload)
    assert res.status_code == 200
    data = res.json()

    assert data["incident_id"] == "INC-000002"
    assert data["event_id"] == "EVT000002"
    assert data["prediction"] == "SQL Injection Attempt"
    assert data["actual_feedback"] == "Automated security scanner probe"
    assert data["resulting_status"] == "False Positive"

    # Verify Global Feedback endpoint
    res_global = client.get("/api/v1/feedback")
    assert res_global.status_code == 200
    global_items = res_global.json()
    assert len(global_items) >= 1
    assert any(fb["incident_id"] == "INC-000002" for fb in global_items)


# ── Test 12: M1, M2, M3 Endpoints Regression ──────────────────────────────────

def test_all_previous_milestone_endpoints_regression():
    client = TestClient(app)

    # M1 Endpoints
    assert client.get("/events").status_code == 200
    assert client.get("/stats").status_code == 200
    assert client.get("/threats").status_code == 200
    assert client.get("/threat-intel").status_code == 200
    assert client.get("/vulnerabilities").status_code == 200

    # M2 Endpoints
    assert client.get("/predictions").status_code == 200
    assert client.get("/model-performance").status_code == 200
    assert client.get("/threat-summary").status_code == 200
    assert client.get("/top-predictions").status_code == 200

    # M3 Endpoints
    assert client.get("/api/v1/risk/weights").status_code == 200
    assert client.get("/api/v1/risk/summary").status_code == 200
    assert client.get("/api/v1/incidents").status_code == 200
    assert client.get("/api/v1/attack-chains").status_code == 200
