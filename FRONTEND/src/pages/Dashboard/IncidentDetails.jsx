import React, { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import {
  FiArrowLeft,
  FiAlertTriangle,
  FiClock,
  FiServer,
  FiUser,
  FiCheckCircle,
  FiActivity,
  FiList,
  FiRefreshCw,
  FiArrowRight,
} from "react-icons/fi";

import ErrorBanner from "../../components/ErrorBanner";
import { RiskLevelBadge, PriorityBadge, StatusBadge, RiskScoreBadge } from "../../components/m3/RiskBadge";
import RiskBreakdownCard from "../../components/m3/RiskBreakdownCard";
import RiskScoreComparisonCard from "../../components/m3/RiskScoreComparisonCard";
import SecurityIntelligenceCard from "../../components/m3/SecurityIntelligenceCard";
import AttackChainTimeline from "../../components/m3/AttackChainTimeline";
import RecommendationsPanel from "../../components/m3/RecommendationsPanel";
import AnalystFeedbackModal from "../../components/m3/AnalystFeedbackModal";
import AnalystFeedbackCard from "../../components/m3/AnalystFeedbackCard";
import {
  getIncidentById,
  updateIncidentStatus,
  getAnalystFeedback,
  INCIDENT_STATUS_OPTIONS,
} from "../../services/api";

export default function IncidentDetails() {
  const { id: incidentId } = useParams();

  const [incident, setIncident] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [statusUpdating, setStatusUpdating] = useState(false);
  const [statusSuccess, setStatusSuccess] = useState(null);
  const [statusError, setStatusError] = useState(null);

  const [isFeedbackModalOpen, setIsFeedbackModalOpen] = useState(false);
  const [feedbackHistory, setFeedbackHistory] = useState([]);

  async function loadIncident() {
    if (!incidentId) return;
    setLoading(true);
    setError(null);
    try {
      const data = await getIncidentById(incidentId);
      setIncident(data);

      // Load feedback history if incident is False Positive or has feedback
      try {
        const fbData = await getAnalystFeedback(incidentId);
        setFeedbackHistory(fbData || []);
      } catch {
        // Fallback to embedded feedback if separate call fails
        setFeedbackHistory(data.feedback || []);
      }
    } catch (err) {
      setError(err.message || `Failed to load incident '${incidentId}'`);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadIncident();
  }, [incidentId]);

  async function handleStatusChange(newStatus) {
    if (!incident || incident.status === newStatus) return;

    // If selecting False Positive, prompt analyst for structured feedback rationale
    if (newStatus === "False Positive") {
      setIsFeedbackModalOpen(true);
      return;
    }

    setStatusUpdating(true);
    setStatusSuccess(null);
    setStatusError(null);
    try {
      const updated = await updateIncidentStatus(incident.incident_id, newStatus);
      setIncident(updated);
      setStatusSuccess(`Incident status successfully updated to '${newStatus}'.`);
      setTimeout(() => setStatusSuccess(null), 4000);
    } catch (err) {
      const msg = err.message || "Failed to update incident status.";
      setStatusError(msg);
      setTimeout(() => setStatusError(null), 5000);
    } finally {
      setStatusUpdating(false);
    }
  }

  function handleFeedbackSubmitted() {
    setStatusSuccess("Incident marked as False Positive with structured analyst feedback recorded.");
    setTimeout(() => setStatusSuccess(null), 5000);
    loadIncident();
  }

  if (loading) {
    return (
      <div className="py-20 flex flex-col items-center justify-center space-y-3">
        <div className="w-8 h-8 rounded-full border-3 border-blue-500 border-t-transparent animate-spin" />
        <p className="text-xs text-slate-400 font-medium">Loading incident investigation context...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="space-y-4">
        <Link
          to="/dashboard/incidents"
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-blue-400 hover:text-blue-300 transition-colors"
        >
          <FiArrowLeft className="text-sm" />
          <span>Back to Priority Incidents Queue</span>
        </Link>
        <ErrorBanner message={error} onRetry={loadIncident} />
      </div>
    );
  }

  if (!incident) {
    return (
      <div className="space-y-4">
        <Link
          to="/dashboard/incidents"
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-blue-400 hover:text-blue-300 transition-colors"
        >
          <FiArrowLeft className="text-sm" />
          <span>Back to Priority Incidents Queue</span>
        </Link>
        <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-8 text-center text-xs text-slate-400">
          Incident not found for ID '{incidentId}'.
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Navigation Breadcrumb */}
      <div className="flex items-center justify-between">
        <Link
          to="/dashboard/incidents"
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-blue-400 hover:text-blue-300 transition-colors"
        >
          <FiArrowLeft className="text-sm" />
          <span>Back to Priority Incidents Queue</span>
        </Link>

        <button
          onClick={loadIncident}
          disabled={loading}
          className="inline-flex items-center gap-1 text-xs text-slate-400 hover:text-slate-200"
        >
          <FiRefreshCw className={loading ? "animate-spin text-xs" : "text-xs"} />
          <span>Reload Details</span>
        </button>
      </div>

      {/* Success Notification Banner */}
      {statusSuccess && (
        <div className="bg-emerald-500/15 border border-emerald-500/30 rounded-xl p-3.5 flex items-center gap-2.5 text-xs text-emerald-300">
          <FiCheckCircle className="text-emerald-400 text-sm shrink-0" />
          <span>{statusSuccess}</span>
        </div>
      )}

      {/* Status Error Notification Banner */}
      {statusError && (
        <div className="bg-red-500/15 border border-red-500/30 rounded-xl p-3.5 flex items-center gap-2.5 text-xs text-red-300">
          <FiAlertTriangle className="text-red-400 text-sm shrink-0" />
          <span>{statusError}</span>
        </div>
      )}

      {/* Primary Incident Header Card */}
      <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-5 md:p-6 space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-[#1F2937] pb-4">
          <div className="flex items-start gap-4">
            <RiskScoreBadge score={incident.risk_score} level={incident.risk_level} size="lg" />
            <div>
              <div className="flex items-center gap-2.5 flex-wrap">
                <span className="font-mono text-sm font-bold text-blue-400">{incident.incident_id}</span>
                <h2 className="text-lg md:text-xl font-extrabold text-slate-100">{incident.threat_type}</h2>
                <RiskLevelBadge level={incident.risk_level} size="sm" />
                <PriorityBadge priority={incident.priority} size="sm" />
              </div>
              <div className="flex items-center gap-4 text-xs text-slate-400 mt-1 flex-wrap font-mono">
                <span className="flex items-center gap-1">
                  <FiClock className="text-slate-500" />
                  {incident.created_at || "N/A"}
                </span>
                <span className="flex items-center gap-1 text-slate-300">
                  <FiServer className="text-slate-500" />
                  Asset: <strong className="text-slate-100">{incident.asset_name || "Unknown"}</strong> ({incident.asset_id || "AST-N/A"})
                </span>
                <span className="flex items-center gap-1 text-slate-300">
                  <FiUser className="text-slate-500" />
                  User: <strong className="text-slate-100">{incident.affected_user || "system"}</strong>
                </span>
                {incident.source_ip && (
                  <span className="flex items-center gap-1 text-slate-300">
                    Src IP: <strong className="text-blue-400 font-mono">{incident.source_ip}</strong>
                  </span>
                )}
                {incident.destination_ip && (
                  <span className="flex items-center gap-1 text-slate-300">
                    Dst IP: <strong className="text-slate-200 font-mono">{incident.destination_ip}</strong>
                  </span>
                )}
              </div>
            </div>
          </div>

          {/* Lifecycle Status Selector (Phase 3L) */}
          <div className="flex items-center gap-2.5 bg-[#1E293B] border border-[#1F2937] rounded-lg p-2 shrink-0">
            <span className="text-xs text-slate-400 font-semibold pl-1">Status:</span>
            <select
              value={incident.status || "Open"}
              onChange={(e) => handleStatusChange(e.target.value)}
              disabled={statusUpdating}
              className="rounded bg-[#111827] border border-[#1F2937] px-3 py-1 text-xs font-semibold text-slate-200 focus:outline-none focus:border-blue-500 cursor-pointer disabled:opacity-50"
            >
              {INCIDENT_STATUS_OPTIONS.map((st) => (
                <option key={st} value={st}>{st}</option>
              ))}
            </select>
            <StatusBadge status={incident.status} size="sm" />
          </div>
        </div>

        {/* Quick Meta Chips — Full Investigation Attributes */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 pt-1">
          <div className="bg-[#1E293B]/70 border border-[#1F2937] rounded-lg p-2.5" title="Confidence assigned by the threat detection model">
            <span className="text-[10px] uppercase font-bold text-slate-400 block">AI Detection Confidence</span>
            <span className="text-sm font-mono font-bold text-blue-400">{incident.ml_confidence}%</span>
          </div>
          <div className="bg-[#1E293B]/70 border border-[#1F2937] rounded-lg p-2.5" title="Common Vulnerability Scoring System severity rating">
            <span className="text-[10px] uppercase font-bold text-slate-400 block">CVE & Severity (CVSS)</span>
            <span className={`text-sm font-mono font-bold block truncate ${incident.cvss_score >= 9 ? "text-red-400" : incident.cvss_score >= 7 ? "text-orange-400" : "text-slate-200"}`}>
              {incident.cve_id || "CVE-2025"} ({incident.cvss_score !== null && incident.cvss_score !== undefined ? incident.cvss_score.toFixed(1) : "N/A"})
            </span>
          </div>
          <div className="bg-[#1E293B]/70 border border-[#1F2937] rounded-lg p-2.5" title="Correlated Indicators of Compromise from Threat Intelligence">
            <span className="text-[10px] uppercase font-bold text-slate-400 block">Threat Intelligence</span>
            <span className={`text-sm font-bold truncate block ${incident.ioc_status === "Malicious" ? "text-red-400" : "text-emerald-400"}`}>
              {incident.ioc_status || "Clean"} {incident.ioc_value ? `(${incident.ioc_value})` : ""}
            </span>
          </div>
          <div className="bg-[#1E293B]/70 border border-[#1F2937] rounded-lg p-2.5" title="Adversary behavior mapped to the MITRE ATT&CK framework">
            <span className="text-[10px] uppercase font-bold text-slate-400 block">MITRE ATT&CK</span>
            <span className="text-sm font-mono font-bold text-purple-300 truncate block">
              {incident.mitre_technique || incident.mitre_techniques?.[0] || "T1190"}
            </span>
          </div>
          <div className="bg-[#1E293B]/70 border border-[#1F2937] rounded-lg p-2.5">
            <span className="text-[10px] uppercase font-bold text-slate-400 block">Source IP</span>
            <span className="text-sm font-mono font-semibold text-blue-300 truncate block">
              {incident.source_ip || "10.0.0.1"}
            </span>
          </div>
          <div className="bg-[#1E293B]/70 border border-[#1F2937] rounded-lg p-2.5">
            <span className="text-[10px] uppercase font-bold text-slate-400 block">Attack Chain</span>
            <span className="text-sm font-bold text-purple-300 truncate block">
              {incident.attack_chain_detected ? incident.attack_chain_type || "Detected" : "None"}
            </span>
          </div>
        </div>

        {/* Prominent Callout: WHY IS THIS INCIDENT RISKY? */}
        {incident.reasons && incident.reasons.length > 0 && (
          <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 space-y-2">
            <div className="flex items-center gap-2">
              <FiAlertTriangle className="text-red-400 text-base shrink-0" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-red-300">
                Why Is This Incident Risky? (SOC Explainability Summary)
              </h3>
            </div>
            <ul className="grid grid-cols-1 md:grid-cols-2 gap-2 pt-1">
              {incident.reasons.map((reason, idx) => (
                <li key={idx} className="flex items-start gap-2 text-xs text-slate-200">
                  <span className="h-1.5 w-1.5 rounded-full bg-red-400 mt-1.5 shrink-0" />
                  <span>{reason}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* Analyst Quick Workflow Actions (Phase 10 & 11) */}
      <div className="flex items-center justify-between flex-wrap gap-2.5 bg-[#111827] border border-[#1F2937] rounded-xl p-3.5">
        <div className="flex items-center gap-2">
          <span className="text-xs font-bold text-slate-200">Analyst Workflow Actions:</span>
          <span className="text-[11px] text-slate-400">Update lifecycle status or submit feedback</span>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={() => handleStatusChange("Investigating")}
            disabled={statusUpdating || incident.status === "Investigating"}
            className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold shadow-xs transition-colors disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
          >
            Mark Investigating
          </button>
          <button
            onClick={() => handleStatusChange("Resolved")}
            disabled={statusUpdating || incident.status === "Resolved"}
            className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-semibold shadow-xs transition-colors disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
          >
            Mark Resolved
          </button>
          <button
            onClick={() => handleStatusChange("False Positive")}
            disabled={statusUpdating || incident.status === "False Positive"}
            className="px-3 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-700 text-white text-xs font-semibold shadow-xs transition-colors disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
          >
            Mark False Positive
          </button>
        </div>
      </div>

      {/* 1. Risk Explainability Factor Breakdown (Phase 3F & 3G) */}
      <RiskBreakdownCard
        riskScore={incident.risk_score}
        riskLevel={incident.risk_level}
        priority={incident.priority}
        breakdown={incident.risk_breakdown}
        reasons={incident.reasons}
      />

      {/* 1b. Risk Score Comparison — Before vs After Correlation (Phase 4 Feature 3) */}
      <RiskScoreComparisonCard
        comparison={incident.risk_score_comparison}
        incident={incident}
      />

      {/* 2. Security Intelligence Facets (Phase 3J) */}
      <SecurityIntelligenceCard incident={incident} />

      {/* 3. Attack Chain Visualization Timeline (Phase 3H & 3I - Animated) */}
      <AttackChainTimeline attackChain={incident.attack_chain} />

      {/* 4. Advisory SOC Response Recommendations (Phase 3K) */}
      <RecommendationsPanel recommendations={incident.recommendations} />

      {/* 4b. Analyst False Positive Audit Feedback (Phase 4 Feature 4) */}
      <AnalystFeedbackCard
        feedbackList={feedbackHistory && feedbackHistory.length > 0 ? feedbackHistory : incident.feedback}
      />

      {/* 4c. Incident Lifecycle Status History Audit Trail */}
      {incident.status_history && incident.status_history.length > 0 && (
        <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-5 md:p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-[#1F2937] pb-3">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-blue-500/15 text-blue-400 border border-blue-500/30">
                <FiActivity className="text-base" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-slate-100">Incident Lifecycle Audit Trail</h3>
                <p className="text-xs text-slate-400">Complete historical timeline of status transitions and analyst actions</p>
              </div>
            </div>
            <span className="text-[11px] font-semibold px-2 py-0.5 rounded bg-[#1E293B] text-slate-300 border border-[#1F2937]">
              {incident.status_history.length} Event{incident.status_history.length > 1 ? "s" : ""}
            </span>
          </div>

          <div className="relative pl-4 space-y-3 before:absolute before:left-1.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-[#1F2937]">
            {incident.status_history.map((record, idx) => (
              <div key={idx} className="relative flex items-start gap-3 text-xs">
                <div className="w-2.5 h-2.5 rounded-full bg-blue-500 ring-4 ring-[#111827] mt-1 shrink-0" />
                <div className="flex-1 bg-[#1E293B]/70 border border-[#1F2937] rounded-lg p-3 space-y-1.5">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <StatusBadge status={record.status} />
                      <span className="text-slate-400 text-[11px] flex items-center gap-1">
                        <FiUser className="text-slate-500 text-xs" />
                        By <strong className="text-slate-200 font-medium">{record.changed_by || "SOC Analyst"}</strong>
                      </span>
                    </div>
                    <span className="text-[11px] text-slate-400 font-mono flex items-center gap-1">
                      <FiClock className="text-xs" />
                      {record.changed_at}
                    </span>
                  </div>
                  {record.reason && (
                    <p className="text-slate-300 text-[11px] bg-[#0F172A] border border-[#1E293B] rounded px-2 py-1">
                      {record.reason}
                    </p>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 5. Correlated Security Events List */}
      <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-5 space-y-3">
        <div className="flex items-center justify-between border-b border-[#1F2937] pb-3">
          <div className="flex items-center gap-2">
            <FiList className="text-blue-400" />
            <h3 className="text-sm font-bold text-slate-100">Correlated Event Timeline ({incident.event_ids?.length || 1} Events)</h3>
          </div>
          <span className="text-xs text-slate-400">15-minute sliding correlation window</span>
        </div>

        <div className="flex flex-wrap gap-2 pt-1">
          {incident.event_ids?.map((eid) => (
            <Link
              key={eid}
              to={`/dashboard/events/${eid}`}
              title={`Inspect atomic telemetry event ${eid}`}
              className={`font-mono text-xs px-2.5 py-1 rounded-md border transition-all hover:scale-105 flex items-center gap-1.5 ${
                eid.includes(incident.incident_id.replace("INC-", "")) || eid === incident.event_ids[0]
                  ? "bg-blue-600/25 text-blue-300 border-blue-500/40 font-bold hover:bg-blue-600/40"
                  : "bg-[#1E293B] text-slate-300 border-[#1F2937] hover:bg-slate-700 hover:text-white"
              }`}
            >
              <span>{eid}</span>
              {eid === incident.event_ids[0] && (
                <span className="text-[10px] text-blue-400 font-bold">(Anchor)</span>
              )}
              <FiArrowRight className="text-[10px] opacity-70" />
            </Link>
          ))}
        </div>
      </div>

      {/* False Positive Feedback Modal */}
      <AnalystFeedbackModal
        isOpen={isFeedbackModalOpen}
        incidentId={incident.incident_id}
        onClose={() => setIsFeedbackModalOpen(false)}
        onFeedbackSubmitted={handleFeedbackSubmitted}
      />
    </div>
  );
}
