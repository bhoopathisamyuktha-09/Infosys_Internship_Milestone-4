from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any


# ── Phase 1: Enrichment Schemas ───────────────────────────────────────────────

class EnrichmentAsset(BaseModel):
    found: bool
    asset_id: Optional[str] = None
    asset_name: Optional[str] = None
    asset_type: Optional[str] = None
    owner: Optional[str] = None
    department: Optional[str] = None
    criticality: Optional[str] = None
    criticality_norm: Optional[int] = None


class EnrichmentVulnerability(BaseModel):
    found: bool
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_norm: Optional[int] = None


class EnrichmentMitre(BaseModel):
    found: bool
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    tactic: Optional[str] = None


class EnrichmentThreatIntel(BaseModel):
    found: bool
    ioc_value: Optional[str] = None
    ioc_type: Optional[str] = None
    threat_name: Optional[str] = None        # e.g. "Web App Exploitation Campaign"
    threat_actor: Optional[str] = None       # The actual threat_actor field from DB, e.g. "Unknown"
    confidence: Optional[str] = None         # e.g. "High", "Critical"
    severity: Optional[str] = None           # e.g. "High", "Critical"
    threat_score: Optional[int] = None       # Normalized 0-100
    ioc_matched_field: Optional[str] = None  # "source_ip" or "destination_ip"


class EnrichmentResult(BaseModel):
    asset: EnrichmentAsset
    vulnerability: EnrichmentVulnerability
    mitre: EnrichmentMitre
    threat_intel: EnrichmentThreatIntel


# ── Phase 1: Risk Scoring Schemas ─────────────────────────────────────────────

class RiskFactor(BaseModel):
    name: str
    value: int
    weight: float
    contribution: float  # Preserves decimal precision (e.g. 22.5); final score is rounded int
    reason: str


class RiskBreakdown(BaseModel):
    factors: List[RiskFactor]


class RiskResult(BaseModel):
    score: int = Field(..., ge=0, le=100)
    level: str  # Low, Medium, Moderate, High, Critical
    priority: str  # LOW, MEDIUM, HIGH, HIGH_IMMEDIATE, CRITICAL_IMMEDIATE
    breakdown: RiskBreakdown


# ── Phase 2A: Correlation Schemas ─────────────────────────────────────────────

class CorrelatedEventSummary(BaseModel):
    event_id: str
    timestamp: str
    event_type: str
    username: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    asset_name: Optional[str] = None
    severity: Optional[str] = None


class CorrelationResult(BaseModel):
    related_event_ids: List[str] = []
    related_events_count: int = 0
    correlation_keys: List[str] = []
    time_window_minutes: int = 15
    chronological_events: List[CorrelatedEventSummary] = []


# ── Phase 2B: Attack Chain Schemas ────────────────────────────────────────────

class AttackChainStage(BaseModel):
    stage_order: int
    stage_name: str
    event_id: str
    event_type: str
    timestamp: str
    tactic: Optional[str] = None
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None


class AttackChainResult(BaseModel):
    attack_chain_id: Optional[str] = None    # Deterministic ID e.g. AC-INC-000058 or AC-EVT000058
    attack_chain_detected: bool = False
    attack_chain_type: Optional[str] = None
    confidence: Optional[str] = None         # Correlation/chain detection confidence (e.g. "High", "Medium")
    description: Optional[str] = None
    stages: List[AttackChainStage] = []
    event_ids: List[str] = []
    timeline: List[Dict[str, Any]] = []


# ── Phase 2D: Recommendations Schemas ─────────────────────────────────────────

class Recommendation(BaseModel):
    action: str
    reason: str
    priority: str  # LOW, MEDIUM, HIGH, CRITICAL


class RecommendationResult(BaseModel):
    incident_id: Optional[str] = None
    threat_type: str
    recommendations: List[Recommendation] = []


# ── Advanced Features: Dynamic Risk Weights ───────────────────────────────────

class RiskWeightsModel(BaseModel):
    threat_severity: float = Field(..., ge=0.0, le=1.0)
    ml_confidence: float = Field(..., ge=0.0, le=1.0)
    asset_criticality: float = Field(..., ge=0.0, le=1.0)
    vulnerability_cvss: float = Field(..., ge=0.0, le=1.0)
    threat_intelligence: float = Field(..., ge=0.0, le=1.0)
    updated_at: Optional[str] = None


class RiskWeightsUpdateRequest(BaseModel):
    threat_severity: float = Field(..., ge=0.0, le=1.0, description="Weight for Threat Severity (0-1)")
    ml_confidence: float = Field(..., ge=0.0, le=1.0, description="Weight for ML Confidence (0-1)")
    asset_criticality: float = Field(..., ge=0.0, le=1.0, description="Weight for Asset Criticality (0-1)")
    vulnerability_cvss: float = Field(..., ge=0.0, le=1.0, description="Weight for Vulnerability CVSS (0-1)")
    threat_intelligence: float = Field(..., ge=0.0, le=1.0, description="Weight for Threat Intelligence (0-1)")


# ── Advanced Features: Risk Score Comparison ─────────────────────────────────

class RiskScoreComparison(BaseModel):
    before_correlation: int = Field(..., ge=0, le=100)
    after_correlation: int = Field(..., ge=0, le=100)
    change: int = 0
    change_reason: str
    related_events_count: int = 0
    attack_chain_detected: bool = False
    attack_chain_type: Optional[str] = None
    correlation_keys: List[str] = []
    time_window_minutes: int = 15


# ── Advanced Features: Analyst Feedback Loop ──────────────────────────────────

ALLOWED_FEEDBACK_REASONS = [
    "Benign administrative activity",
    "Expected user behavior",
    "Security scanner / automated tool",
    "Incorrect threat classification",
    "Incorrect enrichment",
    "Excessive sensitivity",
    "Other",
]


class AnalystFeedbackCreate(BaseModel):
    reason: str
    comment: Optional[str] = Field(None, max_length=1000)
    analyst: Optional[str] = "SOC Analyst"
    event_id: Optional[str] = None
    prediction: Optional[str] = None
    actual_feedback: Optional[str] = None


class AnalystFeedbackRecord(BaseModel):
    feedback_id: str
    incident_id: str
    reason: str
    comment: Optional[str] = None
    analyst: str = "SOC Analyst"
    resulting_status: str = "False Positive"
    created_at: str
    event_id: Optional[str] = None
    prediction: Optional[str] = None
    actual_feedback: Optional[str] = None
    timestamp: Optional[str] = None


# ── Phase 2E: Incident Schemas ────────────────────────────────────────────────

VALID_INCIDENT_STATUSES = ["Open", "Investigating", "Resolved", "False Positive"]


class IncidentStatusAuditRecord(BaseModel):
    status: str
    changed_by: str = "SOC Analyst"
    changed_at: str
    reason: Optional[str] = None


class IncidentStatusUpdate(BaseModel):
    status: str = Field(..., description="Status must be one of: Open, Investigating, Resolved, False Positive")
    changed_by: Optional[str] = "SOC Analyst"
    reason: Optional[str] = None


class IncidentDocument(BaseModel):
    incident_id: str
    anchor_event_id: str  # The event that triggered this incident (first in event_ids)
    event_ids: List[str]
    threat_type: str
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: str
    priority: str
    asset_id: Optional[str] = None
    asset_name: Optional[str] = None
    department: Optional[str] = None
    affected_user: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    severity: Optional[str] = None
    ml_confidence: float
    anomaly_score: float
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    ioc_status: Optional[str] = None
    ioc_value: Optional[str] = None
    ioc_matched_field: Optional[str] = None
    ioc_type: Optional[str] = None           # e.g. "IP Address"
    ioc_confidence: Optional[str] = None     # e.g. "High", "Critical"
    ioc_severity: Optional[str] = None       # e.g. "High", "Critical"
    threat_name: Optional[str] = None        # e.g. "Web App Exploitation Campaign"
    threat_actor: Optional[str] = None       # Actual threat_actor field from threat_intelligence DB
    mitre_techniques: List[str] = []
    related_events_count: int = 0
    attack_chain_detected: bool = False
    attack_chain_type: Optional[str] = None
    attack_chain: Optional[AttackChainResult] = None
    risk_breakdown: RiskBreakdown
    risk_score_comparison: Optional[RiskScoreComparison] = None
    reasons: List[str] = []
    recommendations: List[Recommendation] = []
    status: str = "Open"
    status_history: List[IncidentStatusAuditRecord] = []
    feedback: Optional[List[AnalystFeedbackRecord]] = None
    related_events: Optional[List[Dict[str, Any]]] = None
    created_at: str
    updated_at: Optional[str] = None


# ── Phase 2J: API Request/Response Schemas ────────────────────────────────────

class RiskCalculateRequest(BaseModel):
    event_id: str


class RiskCalculateResponse(BaseModel):
    event_id: str
    risk_score: int
    risk_level: str
    priority: str
    risk_breakdown: RiskBreakdown
    risk_score_comparison: Optional[RiskScoreComparison] = None
    reasons: List[str]
    related_events_count: int
    attack_chain: Optional[AttackChainResult] = None


class RiskSummaryResponse(BaseModel):
    total_incidents: int
    critical_count: int
    high_count: int
    moderate_count: int
    medium_count: int
    low_count: int
    open_count: int
    investigating_count: int
    resolved_count: int
    false_positive_count: int
    risk_distribution: Dict[str, int]
    trend: List[Dict[str, Any]] = []
