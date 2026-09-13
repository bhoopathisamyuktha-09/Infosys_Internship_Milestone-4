"""
models/m4_schemas.py — Milestone 4 Pydantic Schemas
===================================================
Milestone 4: Backend Final Integration, API Completion & Production Hardening

Provides schemas for:
  1. Consolidated Dashboard Overview API
  2. Deterministic Security Posture Engine
  3. IOC Intelligence Aggregation
  4. Vulnerability Intelligence Aggregation
  5. Executive Summary API
  6. Security Report API
  7. Semantic Analyst Feedback
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ── 1. Security Posture Schemas ───────────────────────────────────────────────

class SecurityPostureFactor(BaseModel):
    raw_value: Any
    normalized_score: float = Field(..., ge=0.0, le=100.0)
    weight: float = Field(..., ge=0.0, le=1.0)
    points_deducted: float
    explanation: str


class SecurityPostureResponse(BaseModel):
    posture_score: int = Field(..., ge=0, le=100)
    posture_label: str  # Excellent | Good | Needs Attention | Critical
    baseline: float = 100.0
    total_deduction: float
    contributing_factors: Dict[str, SecurityPostureFactor]
    calculation_explanation: str
    calculated_at: str


# ── 2. Dashboard Overview Schemas ─────────────────────────────────────────────

class DashboardOverviewResponse(BaseModel):
    time_range: str
    window_start: Optional[str] = None
    window_end: Optional[str] = None
    total_security_events: int
    detected_threats: int
    critical_threats: int
    high_risk_incidents: int
    active_incidents: int
    affected_assets: int
    threat_severity_distribution: Dict[str, int]
    threat_type_distribution: List[Dict[str, Any]]
    incident_status_distribution: Dict[str, int]
    risk_trend: List[Dict[str, Any]]
    top_critical_incidents: List[Dict[str, Any]]
    security_posture: Dict[str, Any]


# ── 3. IOC Intelligence Aggregation Schemas ───────────────────────────────────

class IocAggregatedItem(BaseModel):
    indicator_id: Optional[str] = None
    indicator_value: str
    indicator_type: str
    malicious_status: str
    threat_count: int
    affected_asset_count: int
    affected_assets: List[str]
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    threat_name: Optional[str] = None
    threat_actor: Optional[str] = None
    confidence: Optional[str] = None
    severity: Optional[str] = None


class IocAggregatedResponse(BaseModel):
    total: int
    limit: int
    skip: int
    items: List[IocAggregatedItem]


class IocSummaryResponse(BaseModel):
    total_indicators: int
    malicious_indicators: int
    suspicious_indicators: int
    correlated_events_total: int
    affected_assets_count: int
    type_distribution: Dict[str, int]
    severity_distribution: Dict[str, int]


# ── 4. Vulnerability Intelligence Aggregation Schemas ─────────────────────────

class VulnerabilitySummaryResponse(BaseModel):
    total_vulnerabilities: int
    critical_cves: int
    high_cves: int
    medium_cves: int
    low_cves: int
    affected_assets_count: int
    top_vulnerable_assets: List[Dict[str, Any]]
    status_distribution: Dict[str, int]
    patch_availability: Dict[str, int]


class PaginatedVulnerabilitiesResponse(BaseModel):
    total: int
    limit: int
    skip: int
    items: List[Dict[str, Any]]


# ── 5. Executive Summary Schemas ──────────────────────────────────────────────

class ExecutiveSummaryResponse(BaseModel):
    report_date: str
    security_posture: Dict[str, Any]
    critical_threats: int
    open_incidents: int
    critical_vulnerabilities: int
    affected_assets: int
    threat_trend: List[Dict[str, Any]]
    risk_distribution: Dict[str, int]
    top_threat_categories: List[Dict[str, Any]]
    top_vulnerable_assets: List[Dict[str, Any]]


# ── 6. Security Report Schemas ────────────────────────────────────────────────

class SecurityReportResponse(BaseModel):
    report_title: str
    generated_at: str
    total_events: int
    detected_threats: int
    critical_incidents: int
    high_risk_assets: int
    security_posture: Dict[str, Any]
    critical_vulnerabilities: int = 0
    total_attack_chains: int = 0
    top_threats: List[Dict[str, Any]]
    top_mitre_techniques: List[Dict[str, Any]]
    top_vulnerabilities: List[Dict[str, Any]]
    attack_chains: List[Dict[str, Any]]
    recommendations: List[Dict[str, Any]]


# ── 7. Semantic Analyst Feedback Schemas ──────────────────────────────────────

class AnalystFeedbackCreateM4(BaseModel):
    event_id: Optional[str] = None
    incident_id: Optional[str] = None
    prediction: Optional[str] = None
    actual_feedback: str
    analyst: Optional[str] = "SOC Analyst"
    comment: Optional[str] = None


class AnalystFeedbackM4(BaseModel):
    feedback_id: str
    event_id: Optional[str] = None
    incident_id: Optional[str] = None
    prediction: Optional[str] = None
    actual_feedback: str
    analyst: str
    timestamp: str
    comment: Optional[str] = None
    resulting_status: Optional[str] = "False Positive"
