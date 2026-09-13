import os, sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import pytest
import mongomock

from database.mongo_db import MongoDatabase
from risk.enrichment import enrich_event
from risk.risk_score import calculate_risk, _determine_level


def _setup_mock_db():
    mock_client = mongomock.MongoClient()
    mock_db = mock_client["threat_detection"]
    # Assets collection
    mock_db["assets"].insert_one({"asset_name": "Server01", "criticality": "Critical"})
    # Vulnerabilities collection
    mock_db["vulnerabilities"].insert_one({"cve_id": "CVE-2023-1234", "cvss_score": 9.8})
    # MITRE mapping
    mock_db["mitre_attack_mapping"].insert_one({
        "event_type": "Brute Force",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
    })
    # Threat intelligence collection (High confidence = 80, Malicious / Critical = 100)
    mock_db["threat_intelligence"].insert_one({
        "indicator_value": "192.0.2.1",
        "indicator_type": "IP Address",
        "confidence": "High",
        "severity": "High",
    })
    mock_db["threat_intelligence"].insert_one({
        "indicator_value": "198.51.100.1",
        "indicator_type": "IP Address",
        "confidence": "Critical",
        "severity": "Critical",
        "category": "malicious",
    })

    # Patch the singleton
    mongo_instance = MongoDatabase()
    mongo_instance.client = mock_client
    mongo_instance.db = mock_db
    mongo_instance._connected = True

    from database import mongo_db
    mongo_db.mongo = mongo_instance
    return mock_db


@pytest.fixture(autouse=True)
def load_store(monkeypatch):
    from services.data_store import store
    store._loaded = False
    store.load()
    return store


def test_all_zero_inputs():
    _setup_mock_db()
    event = {
        "asset_name": "UnknownAsset",
        "vulnerability_id": "UNKNOWN",
        "source_ip": "10.0.0.1",
        "event_type": "Unknown",
    }
    enrichment = enrich_event(event)
    result = calculate_risk(enrichment, ml_confidence=0, threat_severity=0)
    assert result.score == 0
    assert result.level == "Low"
    assert result.priority == "LOW"


def test_low_risk_scenario():
    _setup_mock_db()
    event = {
        "asset_name": "Server01",
        "vulnerability_id": "CVE-2023-1234",
        "source_ip": "198.51.100.1",
        "event_type": "Brute Force",
    }
    enrichment = enrich_event(event)
    result = calculate_risk(enrichment, ml_confidence=30, threat_severity=30)
    # Expected: 30*0.25 (7.5) + 30*0.25 (7.5) + 100*0.20 (20) + 98*0.20 (19.6) + 100*0.10 (10) = 64.6 -> 65
    assert result.score == 65
    assert result.level == "High"
    assert result.priority == "HIGH_IMMEDIATE"


def test_critical_risk_boundary():
    _setup_mock_db()
    event = {
        "asset_name": "Server01",
        "vulnerability_id": "CVE-2023-1234",
        "source_ip": "198.51.100.1",
        "event_type": "Brute Force",
    }
    enrichment = enrich_event(event)
    result = calculate_risk(enrichment, ml_confidence=100, threat_severity=100)
    assert result.score == 100
    assert result.level == "Critical"
    assert result.priority == "CRITICAL_IMMEDIATE"


def test_boundary_levels():
    # Direct level mapping verification
    assert _determine_level(0) == "Low"
    assert _determine_level(20) == "Low"
    assert _determine_level(21) == "Medium"
    assert _determine_level(40) == "Medium"
    assert _determine_level(41) == "Moderate"
    assert _determine_level(60) == "Moderate"
    assert _determine_level(61) == "High"
    assert _determine_level(80) == "High"
    assert _determine_level(81) == "Critical"
    assert _determine_level(100) == "Critical"

    # Verification via calculate_risk engine with controlled inputs
    _setup_mock_db()
    empty_enrichment = enrich_event({})

    # Score 20 (Low)
    res20 = calculate_risk(empty_enrichment, ml_confidence=40, threat_severity=40)
    assert res20.score == 20
    assert res20.level == "Low"

    # Score 21 (Medium)
    res21 = calculate_risk(empty_enrichment, ml_confidence=42, threat_severity=42)
    assert res21.score == 21
    assert res21.level == "Medium"

    # Score 40 (Medium)
    res40 = calculate_risk(empty_enrichment, ml_confidence=80, threat_severity=80)
    assert res40.score == 40
    assert res40.level == "Medium"

    # Score 41 (Moderate)
    res41 = calculate_risk(empty_enrichment, ml_confidence=82, threat_severity=82)
    assert res41.score == 41
    assert res41.level == "Moderate"


def test_missing_asset_and_cve():
    _setup_mock_db()
    event = {
        "source_ip": "198.51.100.1",
        "event_type": "Brute Force",
    }
    enrichment = enrich_event(event)
    result = calculate_risk(enrichment, ml_confidence=50, threat_severity=50)
    # Asset and vulnerability contributions are 0, ThreatIntel is 100
    expected_score = int(round(50 * 0.25 + 50 * 0.25 + 0 + 0 + 100 * 0.10))
    assert result.score == expected_score
    assert result.score == 35
    assert result.level == "Medium"


def test_mentor_acceptance_values():
    _setup_mock_db()
    event = {
        "asset_name": "Server01",
        "vulnerability_id": "CVE-2023-1234",
        "source_ip": "192.0.2.1",
        "event_type": "Brute Force",
    }
    enrichment = enrich_event(event)
    # Mentor values: ThreatSeverity 90, MLConfidence 91, AssetCriticality 100, CVSS 98, ThreatIntel 80
    result = calculate_risk(enrichment, ml_confidence=91, threat_severity=90)
    # Expected: 90*0.25=22.5, 91*0.25=22.75, 100*0.20=20, 98*0.20=19.6, 80*0.10=8 => total 92.85 -> rounded 93
    assert result.score == 93
    assert result.level == "Critical"
    assert result.priority == "CRITICAL_IMMEDIATE"


def test_risk_breakdown_contents():
    _setup_mock_db()
    event = {
        "asset_name": "Server01",
        "vulnerability_id": "CVE-2023-1234",
        "source_ip": "198.51.100.1",
        "event_type": "Brute Force",
    }
    enrichment = enrich_event(event)
    result = calculate_risk(enrichment, ml_confidence=50, threat_severity=50)
    factor_names = {f.name for f in result.breakdown.factors}
    assert factor_names == {"ThreatSeverity", "MLConfidence", "AssetCriticality", "VulnCVSS", "ThreatIntel"}

    for f in result.breakdown.factors:
        # Contributions are now floats (rounded to 2 decimal places)
        assert isinstance(f.contribution, float)
        if f.name == "ThreatSeverity":
            assert f.contribution == 12.5   # 50 * 0.25
        elif f.name == "MLConfidence":
            assert f.contribution == 12.5   # 50 * 0.25
        elif f.name == "AssetCriticality":
            assert f.contribution == 20.0   # 100 * 0.20
        elif f.name == "VulnCVSS":
            assert f.contribution == 19.6   # 98 * 0.20
        elif f.name == "ThreatIntel":
            assert f.contribution == 10.0   # 100 * 0.10

    # Verify mentor acceptance precision: 90*0.25=22.5, 91*0.25=22.75
    mentor_event = {
        "asset_name": "Server01",
        "vulnerability_id": "CVE-2023-1234",
        "source_ip": "192.0.2.1",
        "event_type": "Brute Force",
    }
    mentor_enrichment = enrich_event(mentor_event)
    mentor_result = calculate_risk(mentor_enrichment, ml_confidence=91, threat_severity=90)
    assert mentor_result.score == 93
    for f in mentor_result.breakdown.factors:
        if f.name == "ThreatSeverity":
            assert f.contribution == 22.5   # 90 * 0.25
        elif f.name == "MLConfidence":
            assert f.contribution == 22.75  # 91 * 0.25
        elif f.name == "AssetCriticality":
            assert f.contribution == 20.0   # 100 * 0.20
        elif f.name == "VulnCVSS":
            assert f.contribution == 19.6   # 98 * 0.20
        elif f.name == "ThreatIntel":
            assert f.contribution == 8.0    # 80 * 0.10


def test_calculate_risk_with_zero_weights():
    _setup_mock_db()
    event = {
        "asset_name": "Server01",
        "vulnerability_id": "CVE-2023-1234",
        "source_ip": "192.0.2.1",
        "event_type": "Brute Force",
    }
    enrichment = enrich_event(event)

    # Custom weights with 0.0 for threat_severity and asset_criticality
    custom_weights = {
        "threat_severity": 0.0,
        "ml_confidence": 0.50,
        "asset_criticality": 0.0,
        "vulnerability_cvss": 0.30,
        "threat_intelligence": 0.20,
    }

    result = calculate_risk(enrichment, ml_confidence=80, threat_severity=90, weights=custom_weights)
    factors_by_name = {f.name: f for f in result.breakdown.factors}

    assert factors_by_name["ThreatSeverity"].weight == 0.0
    assert factors_by_name["ThreatSeverity"].contribution == 0.0

    assert factors_by_name["AssetCriticality"].weight == 0.0
    assert factors_by_name["AssetCriticality"].contribution == 0.0

    assert factors_by_name["MLConfidence"].weight == 0.50
    assert factors_by_name["MLConfidence"].contribution == 40.0  # 80 * 0.50

    assert factors_by_name["VulnCVSS"].weight == 0.30
    assert factors_by_name["VulnCVSS"].contribution == 29.4  # 98 * 0.30

    assert factors_by_name["ThreatIntel"].weight == 0.20
    assert factors_by_name["ThreatIntel"].contribution == 16.0  # 80 * 0.20

    # Total: 0 + 40 + 0 + 29.4 + 16 = 85.4 => rounded 85 (Critical)
    assert result.score == 85
    assert result.level == "Critical"

