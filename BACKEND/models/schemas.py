from pydantic import BaseModel
from typing import Optional, List, Dict, Any


class MitreInfo(BaseModel):
    id: str
    technique: str
    tactic: str


class Event(BaseModel):
    id: str
    timestamp: str
    time: str
    eventType: str
    severity: str
    sourceIP: str
    destIP: str
    department: str
    status: str
    mitre: MitreInfo
    riskScore: int


class Stats(BaseModel):
    total_events: int
    critical_events: int
    high_events: int
    vulnerabilities: int
    active_incidents: int
    avg_risk_score: int


class ThreatCount(BaseModel):
    event_type: str
    count: int


class ThreatIntelItem(BaseModel):
    indicator_id: str
    indicator_type: str
    indicator_value: str
    threat_name: str
    threat_actor: str
    confidence: str
    severity: str


class VulnerabilityItem(BaseModel):
    vulnerability_id: str
    cve_id: str
    vulnerability_name: str
    severity: str
    cvss_score: float
    affected_asset: str
    status: str
    patch_available: Optional[str] = None


# ---------------------------------------------------------------------------
# Milestone 2 Prediction Schemas
# ---------------------------------------------------------------------------

class PredictionRequest(BaseModel):
    event_id: str
    timestamp: str
    username: Optional[str] = "unknown_user"
    source_ip: Optional[str] = "0.0.0.0"
    destination_ip: Optional[str] = "0.0.0.0"
    protocol: Optional[str] = "TCP"
    source_country: Optional[str] = "India"
    destination_country: Optional[str] = "India"
    hour: Optional[int] = 12
    is_weekend: Optional[bool] = False
    failed_login_attempts: Optional[int] = 0
    status_flag: Optional[int] = 0
    cvss_score: Optional[float] = 0.0
    severity_score: Optional[int] = 0
    malware_flag: Optional[int] = 0
    event_type: Optional[str] = None


class PredictionReason(BaseModel):
    rule_id: str
    reason: str
    points: int
    severity: str


class PredictionModelSignals(BaseModel):
    if_anomaly_normalized: float
    rf_score_normalized: float
    rule_score: float


class PredictionResponse(BaseModel):
    prediction_id: str
    event_id: str
    prediction_timestamp: str
    verdict: str
    confidence_score: float
    predicted_threat_type: str
    rf_top_probability: float
    rf_confidence_note: str
    anomaly_label: str
    anomaly_score: float
    anomaly_score_raw: float
    anomaly_normalized: Optional[float] = None
    rule_score: float
    triggered_rules: List[str]
    reasons: List[PredictionReason]
    model_signals: PredictionModelSignals
    model_metadata: Optional[Dict[str, Any]] = None
    source_event: Optional[Dict[str, Any]] = None
    original_event_type: Optional[str] = None
    original_severity: Optional[int] = None


class PaginatedPredictionResponse(BaseModel):
    items: List[PredictionResponse]
    total: int


class ThreatSummaryItem(BaseModel):
    threat_type: str
    count: int
    avg_confidence: float
    percentage: Optional[float] = None
