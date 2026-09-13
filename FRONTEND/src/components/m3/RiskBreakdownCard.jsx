import React from "react";
import { FiShield, FiAlertTriangle, FiInfo, FiCheckCircle } from "react-icons/fi";
import { RiskLevelBadge, PriorityBadge, RiskScoreBadge } from "./RiskBadge";

const FACTOR_METADATA = {
  ThreatSeverity: { label: "Threat Severity", weightPct: "25%", color: "bg-red-500", text: "text-red-400" },
  MLConfidence: { label: "ML Model Confidence", weightPct: "25%", color: "bg-blue-500", text: "text-blue-400" },
  AssetCriticality: { label: "Asset Criticality", weightPct: "20%", color: "bg-purple-500", text: "text-purple-400" },
  VulnCVSS: { label: "Vulnerability CVSS", weightPct: "20%", color: "bg-orange-500", text: "text-orange-400" },
  ThreatIntel: { label: "Threat Intelligence", weightPct: "10%", color: "bg-emerald-500", text: "text-emerald-400" },
};

export default function RiskBreakdownCard({ riskScore, riskLevel, priority, breakdown, reasons }) {
  const factors = breakdown?.factors || [];

  return (
    <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-5 md:p-6 space-y-6">
      {/* Header Summary */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-[#1F2937] pb-5">
        <div className="flex items-center gap-4">
          <RiskScoreBadge score={riskScore} level={riskLevel} size="lg" />
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-base md:text-lg font-bold text-slate-100" title="Calculated from the project's configured security risk factors">
                Enterprise Risk Score
              </h3>
              <RiskLevelBadge level={riskLevel} size="sm" />
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              5-factor deterministic formula computed by Risk Prioritization Engine
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400 font-medium">Priority Rating:</span>
          <PriorityBadge priority={priority} size="lg" />
        </div>
      </div>

      {/* 5-Factor Weighted Contributions Grid */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">
            5-Factor Contribution Breakdown
          </h4>
          <span className="text-[11px] font-mono text-slate-400">
            Formula: ∑ (Factor × Weight) = <span className="font-bold text-slate-100">{riskScore}/100</span>
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-3">
          {factors.map((factor) => {
            const meta = FACTOR_METADATA[factor.name] || {
              label: factor.name,
              weightPct: `${Math.round(factor.weight * 100)}%`,
              color: "bg-blue-500",
              text: "text-blue-400",
            };
            const maxContrib = factor.weight * 100;
            const barPercent = Math.min(100, Math.max(0, (factor.contribution / maxContrib) * 100));

            return (
              <div
                key={factor.name}
                className="bg-[#1E293B] border border-[#1F2937] rounded-lg p-3.5 flex flex-col justify-between space-y-2 hover:border-slate-700 transition-colors"
              >
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-semibold text-slate-300 truncate" title={meta.label}>
                    {meta.label}
                  </span>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#111827] text-slate-400 border border-[#1F2937]">
                    {meta.weightPct}
                  </span>
                </div>

                <div className="flex items-baseline justify-between mt-1">
                  <span className="text-xl font-extrabold font-mono text-slate-100">
                    +{factor.contribution}
                  </span>
                  <span className="text-xs text-slate-400 font-mono">
                    raw: <span className="text-slate-300 font-semibold">{factor.value}</span>
                  </span>
                </div>

                {/* Contribution Progress Bar */}
                <div className="w-full bg-[#111827] rounded-full h-1.5 overflow-hidden">
                  <div
                    className={`h-full rounded-full ${meta.color}`}
                    style={{ width: `${barPercent}%` }}
                  />
                </div>

                <p className="text-[10px] text-slate-400 truncate mt-1" title={factor.reason}>
                  {factor.reason}
                </p>
              </div>
            );
          })}
        </div>
      </div>

      {/* Risk Reasons & Drivers (Phase 3G) */}
      {reasons && reasons.length > 0 && (
        <div className="border-t border-[#1F2937] pt-4 space-y-2">
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
            <FiInfo className="text-blue-400" />
            <span>Why This Incident is Risky (Explainability Drivers)</span>
          </h4>
          <ul className="grid grid-cols-1 md:grid-cols-2 gap-2 mt-2">
            {reasons.map((reason, idx) => (
              <li
                key={idx}
                className="flex items-start gap-2 text-xs text-slate-300 bg-[#1E293B]/60 border border-[#1F2937] rounded-lg px-3 py-2"
              >
                <span className="h-1.5 w-1.5 rounded-full bg-blue-400 mt-1.5 shrink-0" />
                <span>{reason}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
