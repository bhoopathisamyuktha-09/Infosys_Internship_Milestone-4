// Real backend API service — same function signatures as mockApi.js, so every
// component that used mock data works unchanged after switching the import.
//
// Base URL is configurable via VITE_API_BASE_URL (see .env.example) so this
// works against localhost during development and a deployed backend later
// without code changes.

const BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

async function fetchJson(path) {
  const res = await fetch(`${BASE_URL}${path}`);
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`API error ${res.status} on ${path}: ${body || res.statusText}`);
  }
  return res.json();
}

// ---------------------------------------------------------------------------
// Milestone 1 API Functions
// ---------------------------------------------------------------------------

export async function getEvents(filters = {}) {
  const params = new URLSearchParams();
  if (filters.severity && filters.severity !== "All") params.set("severity", filters.severity);
  if (filters.eventType && filters.eventType !== "All") params.set("event_type", filters.eventType);
  const query = params.toString() ? `?${params.toString()}` : "";
  return fetchJson(`/events${query}`);
}

export async function getStats() {
  return fetchJson("/stats");
}

export async function getThreats() {
  return fetchJson("/threats");
}

export async function getThreatIntel(filters = {}) {
  const params = new URLSearchParams();
  if (filters.severity && filters.severity !== "All") params.set("severity", filters.severity);
  const query = params.toString() ? `?${params.toString()}` : "";
  return fetchJson(`/threat-intel${query}`);
}

export async function getVulnerabilities(filters = {}) {
  const params = new URLSearchParams();
  if (filters.severity && filters.severity !== "All") params.set("severity", filters.severity);
  const query = params.toString() ? `?${params.toString()}` : "";
  return fetchJson(`/vulnerabilities${query}`);
}

export async function createEvent(eventData) {
  const res = await fetch(`${BASE_URL}/events`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(eventData),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`API error ${res.status} on POST /events: ${body || res.statusText}`);
  }
  return res.json();
}

// ---------------------------------------------------------------------------
// Milestone 2 AI Threat Detection API Functions
// ---------------------------------------------------------------------------

export async function getPredictions(filters = {}) {
  const params = new URLSearchParams();
  if (filters.verdict && filters.verdict !== "All") params.set("verdict", filters.verdict);
  if (filters.threat_type && filters.threat_type !== "All") params.set("threat_type", filters.threat_type);
  if (filters.severity && filters.severity !== "All") params.set("severity", filters.severity);
  if (filters.event_id) params.set("event_id", filters.event_id);
  else if (filters.search) params.set("event_id", filters.search);
  if (filters.limit) params.set("limit", filters.limit);
  if (filters.skip !== undefined && filters.skip !== null) params.set("skip", filters.skip);
  const query = params.toString() ? `?${params.toString()}` : "";
  return fetchJson(`/predictions${query}`);
}

export async function getPredictionById(predictionId) {
  if (!predictionId) throw new Error("predictionId is required");
  return fetchJson(`/predictions/${encodeURIComponent(predictionId)}`);
}

export async function getAnomalies(filters = {}) {
  const params = new URLSearchParams();
  if (filters.limit) params.set("limit", filters.limit);
  if (filters.skip !== undefined && filters.skip !== null) params.set("skip", filters.skip);
  const query = params.toString() ? `?${params.toString()}` : "";
  return fetchJson(`/anomalies${query}`);
}

export async function getThreatSummary() {
  return fetchJson("/threat-summary");
}

export async function getModelPerformance() {
  return fetchJson("/model-performance");
}

export async function getPredictionTrend() {
  return fetchJson("/prediction-trend");
}

export async function getTopPredictions(limit = 3) {
  const params = new URLSearchParams();
  if (limit) params.set("limit", limit);
  const query = params.toString() ? `?${params.toString()}` : "";
  return fetchJson(`/top-predictions${query}`);
}

export async function predictEvent(eventData) {
  const res = await fetch(`${BASE_URL}/predict`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(eventData),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`API error ${res.status} on POST /predict: ${body || res.statusText}`);
  }
  return res.json();
}

// Pure, synchronous — computes the AI insight summary from events already in hand
export function computeAiInsights(events) {
  const topRiskEvents = [...events].sort((a, b) => b.riskScore - a.riskScore).slice(0, 3);

  const techniqueCounts = {};
  events.forEach((e) => {
    const key = e.mitre?.id || "N/A";
    techniqueCounts[key] = techniqueCounts[key] || { ...(e.mitre || { id: "N/A", technique: "Unknown", tactic: "Unknown" }), count: 0 };
    techniqueCounts[key].count += 1;
  });
  const topTechniques = Object.values(techniqueCounts).sort((a, b) => b.count - a.count).slice(0, 3);

  return {
    topRiskEvents,
    topTechniques,
    summary: `${topRiskEvents.length} high-risk events detected in the last session, most frequently linked to ${topTechniques[0]?.technique || "unknown techniques"}.`,
  };
}

// Convenience wrapper for callers that don't already have events in hand.
export async function getAiInsights() {
  const events = await getEvents();
  return computeAiInsights(events);
}

export const EVENT_TYPE_OPTIONS = [
  "Brute Force", "Failed Login", "Login Success", "File Access", "Port Scan",
  "Malware Detection", "USB Device Connected", "Privilege Escalation",
  "SQL Injection Attempt", "Phishing Email",
];
export const SEVERITY_OPTIONS = ["Critical", "High", "Medium", "Low"];
export const STATUS_OPTIONS = ["Open", "Investigating", "Resolved", "Closed"];
export const VERDICT_OPTIONS = ["Normal", "Suspicious", "Critical"];

// ---------------------------------------------------------------------------
// Milestone 3 Risk Prioritization & Security Intelligence APIs
// ---------------------------------------------------------------------------

export async function getRiskSummary() {
  return fetchJson("/api/v1/risk/summary");
}

export async function getHighRiskIncidents(params = {}) {
  const q = new URLSearchParams();
  if (params.limit) q.set("limit", params.limit);
  if (params.skip !== undefined && params.skip !== null) q.set("skip", params.skip);
  if (params.min_score !== undefined && params.min_score !== null) q.set("min_score", params.min_score);
  const query = q.toString() ? `?${q.toString()}` : "";
  return fetchJson(`/api/v1/risk/high${query}`);
}

export async function getIncidents(filters = {}) {
  const q = new URLSearchParams();
  if (filters.risk_level && filters.risk_level !== "All") q.set("risk_level", filters.risk_level);
  if (filters.priority && filters.priority !== "All") q.set("priority", filters.priority);
  if (filters.severity && filters.severity !== "All") q.set("severity", filters.severity);
  if (filters.threat_type && filters.threat_type !== "All") q.set("threat_type", filters.threat_type);
  if (filters.asset_name && filters.asset_name !== "All") q.set("asset_name", filters.asset_name);
  if (filters.department && filters.department !== "All") q.set("department", filters.department);
  if (filters.mitre_technique && filters.mitre_technique !== "All") q.set("mitre_technique", filters.mitre_technique);
  if (filters.cve && filters.cve !== "All") q.set("cve", filters.cve);
  if (filters.ioc_status && filters.ioc_status !== "All") q.set("ioc_status", filters.ioc_status);
  if (filters.time_range && filters.time_range !== "all") q.set("time_range", filters.time_range);
  if (filters.start_date) q.set("start_date", filters.start_date);
  if (filters.end_date) q.set("end_date", filters.end_date);
  if (filters.status && filters.status !== "All") q.set("status", filters.status);
  if (filters.limit) q.set("limit", filters.limit);
  if (filters.skip !== undefined && filters.skip !== null) q.set("skip", filters.skip);
  if (filters.sort_by) q.set("sort_by", filters.sort_by);
  if (filters.sort_order) q.set("sort_order", filters.sort_order);
  const query = q.toString() ? `?${q.toString()}` : "";
  return fetchJson(`/api/v1/incidents${query}`);
}

export async function getIncidentById(incidentId) {
  if (!incidentId) throw new Error("incidentId is required");
  return fetchJson(`/api/v1/incidents/${encodeURIComponent(incidentId)}`);
}

export async function getAttackChains(params = {}) {
  const q = new URLSearchParams();
  if (params.limit) q.set("limit", params.limit);
  if (params.skip !== undefined && params.skip !== null) q.set("skip", params.skip);
  const query = q.toString() ? `?${q.toString()}` : "";
  return fetchJson(`/api/v1/attack-chains${query}`);
}

export async function getRecommendations(incidentId) {
  if (!incidentId) throw new Error("incidentId is required");
  return fetchJson(`/api/v1/recommendations/${encodeURIComponent(incidentId)}`);
}

export async function updateIncidentStatus(incidentId, newStatus) {
  if (!incidentId) throw new Error("incidentId is required");
  const res = await fetch(`${BASE_URL}/api/v1/incidents/${encodeURIComponent(incidentId)}/status`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status: newStatus }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`API error ${res.status} on PATCH status: ${body || res.statusText}`);
  }
  return res.json();
}

export async function calculateRisk(eventId) {
  if (!eventId) throw new Error("eventId is required");
  const res = await fetch(`${BASE_URL}/api/v1/risk/calculate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ event_id: eventId }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`API error ${res.status} on POST /risk/calculate: ${body || res.statusText}`);
  }
  return res.json();
}

export async function getRiskWeights() {
  return fetchJson("/api/v1/risk/weights");
}

export async function updateRiskWeights(weights) {
  const res = await fetch(`${BASE_URL}/api/v1/risk/weights`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(weights),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`API error ${res.status} on PUT /risk/weights: ${body || res.statusText}`);
  }
  return res.json();
}

export async function resetRiskWeights() {
  const res = await fetch(`${BASE_URL}/api/v1/risk/weights/reset`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`API error ${res.status} on POST /risk/weights/reset: ${body || res.statusText}`);
  }
  return res.json();
}

export async function submitAnalystFeedback(incidentId, feedback) {
  if (!incidentId) throw new Error("incidentId is required");
  const res = await fetch(`${BASE_URL}/api/v1/incidents/${encodeURIComponent(incidentId)}/feedback`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(feedback),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`API error ${res.status} on POST feedback: ${body || res.statusText}`);
  }
  return res.json();
}

export async function getAnalystFeedback(incidentId) {
  if (!incidentId) throw new Error("incidentId is required");
  return fetchJson(`/api/v1/incidents/${encodeURIComponent(incidentId)}/feedback`);
}

export const FEEDBACK_REASONS = [
  "Benign administrative activity",
  "Expected user behavior",
  "Security scanner / automated tool",
  "Incorrect threat classification",
  "Incorrect enrichment",
  "Excessive sensitivity",
  "Other",
];

export const RISK_LEVEL_OPTIONS = ["Critical", "High", "Moderate", "Medium", "Low"];
export const PRIORITY_OPTIONS = ["CRITICAL_IMMEDIATE", "HIGH_IMMEDIATE", "HIGH", "MEDIUM", "LOW"];
export const INCIDENT_STATUS_OPTIONS = ["Open", "Investigating", "Resolved", "False Positive"];
export const DEPARTMENT_OPTIONS = ["IT", "Finance", "HR", "Engineering", "Legal", "Marketing", "Operations", "Sales", "Support"];
export const MITRE_TECHNIQUE_OPTIONS = [
  { id: "T1190", name: "Exploit Public-Facing Application" },
  { id: "T1068", name: "Exploitation for Privilege Escalation" },
  { id: "T1110", name: "Brute Force" },
  { id: "T1078", name: "Valid Accounts" },
  { id: "T1059", name: "Command and Scripting Interpreter" },
  { id: "T1566", name: "Phishing" },
  { id: "T1046", name: "Network Service Discovery" },
  { id: "T1083", name: "File and Directory Discovery" },
  { id: "T1200", name: "Hardware Additions" },
];

// ---------------------------------------------------------------------------
// Milestone 4 Backend Integration & Reporting API Functions
// ---------------------------------------------------------------------------

export async function getDashboardOverview(params = {}) {
  const q = new URLSearchParams();
  if (params.time_range && params.time_range !== "all") q.set("time_range", params.time_range);
  if (params.start_date) q.set("start_date", params.start_date);
  if (params.end_date) q.set("end_date", params.end_date);
  const query = q.toString() ? `?${q.toString()}` : "";
  return fetchJson(`/api/v1/dashboard/overview${query}`);
}

export async function getSecurityPosture() {
  return fetchJson("/api/v1/dashboard/security-posture");
}

export async function getExecutiveSummary() {
  return fetchJson("/api/v1/executive/summary");
}

export async function getSecurityReportJson() {
  return fetchJson("/api/v1/reports/security");
}

export function getSecurityReportCsvUrl() {
  return `${BASE_URL}/api/v1/reports/security.csv`;
}

export async function getThreatIntelIndicators(params = {}) {
  const q = new URLSearchParams();
  const indicatorType = params.indicator_type || params.ioc_type;
  if (indicatorType && indicatorType !== "All") q.set("indicator_type", indicatorType);
  if (params.severity && params.severity !== "All") q.set("severity", params.severity);
  if (params.status && params.status !== "All") q.set("status", params.status);
  if (params.search && params.search.trim()) q.set("search", params.search.trim());
  if (params.limit) q.set("limit", params.limit);
  if (params.skip !== undefined && params.skip !== null) q.set("skip", params.skip);
  const query = q.toString() ? `?${q.toString()}` : "";
  return fetchJson(`/api/v1/threat-intel/indicators${query}`);
}

export async function getThreatIntelSummary() {
  return fetchJson("/api/v1/threat-intel/summary");
}

export async function getVulnerabilitiesSummary() {
  return fetchJson("/api/v1/vulnerabilities/summary");
}

export async function getPaginatedVulnerabilities(params = {}) {
  const q = new URLSearchParams();
  if (params.severity && params.severity !== "All") q.set("severity", params.severity);
  const patch = params.patch_available || params.patch_status;
  if (patch && patch !== "All") q.set("patch_available", patch);
  if (params.status && params.status !== "All") q.set("status", params.status);
  if (params.affected_asset && params.affected_asset !== "All") q.set("affected_asset", params.affected_asset);
  if (params.search && params.search.trim()) q.set("search", params.search.trim());
  if (params.limit) q.set("limit", params.limit);
  if (params.skip !== undefined && params.skip !== null) q.set("skip", params.skip);
  const query = q.toString() ? `?${q.toString()}` : "";
  return fetchJson(`/api/v1/vulnerabilities${query}`);
}

export async function getEventById(eventId) {
  if (!eventId) throw new Error("eventId is required");
  return fetchJson(`/events/${encodeURIComponent(eventId)}`);
}

export async function getAllAnalystFeedback(params = {}) {
  const q = new URLSearchParams();
  if (params.limit) q.set("limit", params.limit);
  if (params.skip !== undefined && params.skip !== null) q.set("skip", params.skip);
  const query = q.toString() ? `?${q.toString()}` : "";
  return fetchJson(`/api/v1/feedback${query}`);
}

export const INCIDENT_IOC_STATUS_OPTIONS = ["All", "Malicious", "Clean"];
export const THREAT_INTEL_STATUS_OPTIONS = ["All", "Malicious", "Suspicious", "Benign"];
export const IOC_STATUS_OPTIONS = ["All", "Malicious", "Suspicious", "Benign"]; // backwards compatibility
export const IOC_TYPE_OPTIONS = ["All", "IP Address", "Domain", "File Hash (SHA256)", "URL", "Email Address"];
export const PATCH_OPTIONS = ["All", "Yes", "No"];
export const TIME_RANGE_OPTIONS = [
  { label: "All Time", value: "all" },
  { label: "Last 24 Hours", value: "24h" },
  { label: "Last 7 Days", value: "7d" },
  { label: "Last 30 Days", value: "30d" },
];


