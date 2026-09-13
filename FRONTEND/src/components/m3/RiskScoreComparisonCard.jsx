import React from "react";
import {
  FiGitCommit,
  FiTrendingUp,
  FiArrowRight,
  FiInfo,
  FiLayers,
  FiClock,
  FiKey,
} from "react-icons/fi";
import { useTheme } from "../../context/ThemeContext";

export default function RiskScoreComparisonCard({ comparison, incident }) {
  const { isDark } = useTheme();

  if (!comparison && !incident) return null;

  const beforeScore =
    comparison?.before_correlation !== undefined
      ? comparison.before_correlation
      : incident?.risk_score ?? 0;
  const afterScore =
    comparison?.after_correlation !== undefined
      ? comparison.after_correlation
      : incident?.risk_score ?? 0;
  const change = comparison?.change ?? 0;
  const relatedCount =
    comparison?.related_events_count ?? incident?.related_events_count ?? 0;
  const chainDetected =
    comparison?.attack_chain_detected ?? incident?.attack_chain_detected ?? false;
  const chainType =
    comparison?.attack_chain_type ?? incident?.attack_chain_type ?? null;
  const timeWindow = comparison?.time_window_minutes ?? 15;
  const correlationKeys =
    comparison?.correlation_keys && comparison.correlation_keys.length > 0
      ? comparison.correlation_keys
      : ["username", "source_ip", "asset_name"];

  const changeReason =
    comparison?.change_reason ||
    "Correlation increased investigation context but did not alter the base risk score.";

  return (
    <div
      className={`rounded-xl p-5 md:p-6 space-y-4 border transition-colors ${
        isDark ? "bg-[#111827] border-[#1F2937]" : "bg-white border-slate-200 shadow-xs"
      }`}
    >
      {/* Header */}
      <div
        className={`flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b pb-3 ${
          isDark ? "border-[#1F2937]" : "border-slate-200"
        }`}
      >
        <div className="flex items-center gap-2.5">
          <div
            className={`p-1.5 rounded-lg border ${
              isDark
                ? "bg-blue-500/15 text-blue-400 border-blue-500/30"
                : "bg-blue-50 text-blue-700 border-blue-200"
            }`}
          >
            <FiTrendingUp className="text-base" />
          </div>
          <div>
            <h3 className={`text-sm font-bold ${isDark ? "text-slate-100" : "text-slate-900"}`}>
              Risk Score Comparison — Before vs After Correlation
            </h3>
            <p className={`text-xs ${isDark ? "text-slate-400" : "text-slate-600"}`}>
              Deterministic 5-factor evaluation compared with contextual correlation signals
            </p>
          </div>
        </div>

        <div className="flex items-center gap-1.5 self-start sm:self-auto">
          <span className={`text-[11px] font-semibold ${isDark ? "text-slate-400" : "text-slate-600"}`}>
            Delta:
          </span>
          <span
            className={`font-mono text-xs font-bold px-2 py-0.5 rounded border ${
              change > 0
                ? isDark
                  ? "bg-amber-500/20 text-amber-300 border-amber-500/30"
                  : "bg-amber-50 text-amber-800 border-amber-300"
                : change < 0
                ? isDark
                  ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/30"
                  : "bg-emerald-50 text-emerald-800 border-emerald-300"
                : isDark
                ? "bg-slate-800 text-slate-300 border-slate-700"
                : "bg-slate-100 text-slate-700 border-slate-300"
            }`}
          >
            {change >= 0 ? `+${change}` : change} pts
          </span>
        </div>
      </div>

      {/* Before vs After Cards */}
      <div className="grid grid-cols-1 md:grid-cols-11 gap-3 items-center">
        {/* Before Correlation */}
        <div
          className={`md:col-span-5 rounded-xl p-4 space-y-2 border transition-colors ${
            isDark
              ? "bg-[#1E293B]/70 border-[#1F2937]"
              : "bg-slate-50 border-slate-200 shadow-xs"
          }`}
        >
          <div className="flex items-center justify-between">
            <span
              className={`text-[11px] font-bold uppercase tracking-wider ${
                isDark ? "text-slate-400" : "text-slate-600"
              }`}
            >
              Before Correlation
            </span>
            <span
              className={`text-[10px] font-semibold px-2 py-0.5 rounded border ${
                isDark
                  ? "bg-slate-800 text-slate-300 border-slate-700"
                  : "bg-slate-200 text-slate-700 border-slate-300"
              }`}
            >
              Anchor Event Base
            </span>
          </div>
          <div className="flex items-center gap-3 pt-1">
            <div className="text-2xl font-black font-mono text-blue-500">{beforeScore}</div>
            <div className="text-xs">
              <span className={`font-semibold block ${isDark ? "text-slate-100" : "text-slate-900"}`}>
                Single-Event Telemetry
              </span>
              <span className={`text-[11px] ${isDark ? "text-slate-400" : "text-slate-600"}`}>
                5-factor weighted baseline: Threat Severity, AI Detection Confidence, Asset, CVSS, Threat Intel
              </span>
            </div>
          </div>
        </div>

        {/* Transition Indicator */}
        <div className="md:col-span-1 flex items-center justify-center py-1 md:py-0">
          <div
            className={`p-2 rounded-full border ${
              isDark ? "bg-[#1E293B] border-[#1F2937]" : "bg-slate-100 border-slate-300 shadow-xs"
            }`}
          >
            <FiArrowRight className={`text-sm ${isDark ? "text-blue-400" : "text-blue-600"}`} />
          </div>
        </div>

        {/* After Correlation */}
        <div
          className={`md:col-span-5 rounded-xl p-4 space-y-2 border transition-colors ${
            isDark
              ? "bg-[#1E293B]/70 border-[#1F2937]"
              : "bg-purple-50/40 border-purple-200/80 shadow-xs"
          }`}
        >
          <div className="flex items-center justify-between">
            <span
              className={`text-[11px] font-bold uppercase tracking-wider ${
                isDark ? "text-purple-400" : "text-purple-700"
              }`}
            >
              After Correlation
            </span>
            <span
              className={`text-[10px] font-semibold px-2 py-0.5 rounded border ${
                isDark
                  ? "bg-purple-500/20 text-purple-300 border-purple-500/30"
                  : "bg-purple-100 text-purple-800 border-purple-300"
              }`}
            >
              Full Contextual Evaluation
            </span>
          </div>
          <div className="flex items-center gap-3 pt-1">
            <div
              className={`text-2xl font-black font-mono ${
                isDark ? "text-purple-300" : "text-purple-600"
              }`}
            >
              {afterScore}
            </div>
            <div className="text-xs">
              <span className={`font-semibold block ${isDark ? "text-slate-100" : "text-slate-900"}`}>
                Contextual Risk State
              </span>
              <span className={`text-[11px] ${isDark ? "text-slate-400" : "text-slate-600"}`}>
                {chainDetected
                  ? `Correlated with ${relatedCount} events into a validated ${chainType}`
                  : relatedCount > 0
                  ? `Correlated with ${relatedCount} related events in sliding window`
                  : "Isolated single event — no multi-stage threat detected"}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Impact Analysis Panel */}
      <div
        className={`p-4 rounded-xl border space-y-3 transition-colors ${
          isDark
            ? "bg-[#1E293B]/90 border-[#334155] shadow-sm"
            : "bg-blue-50/40 border-blue-200/80 shadow-xs"
        }`}
      >
        <div className="flex items-start gap-2.5 text-xs">
          <div
            className={`p-1 rounded-md shrink-0 mt-0.5 ${
              isDark
                ? "bg-blue-500/15 text-blue-400 border border-blue-500/30"
                : "bg-blue-100 text-blue-700 border border-blue-200"
            }`}
          >
            <FiInfo className="text-sm" />
          </div>
          <div className="leading-relaxed">
            <span className={`font-bold ${isDark ? "text-slate-100" : "text-slate-900"}`}>
              Impact Analysis:{" "}
            </span>
            <span className={isDark ? "text-slate-200" : "text-slate-700"}>
              {changeReason}
            </span>
          </div>
        </div>

        {/* Correlation Context Pills */}
        <div
          className={`grid grid-cols-2 sm:grid-cols-4 gap-3 pt-3 border-t text-[11px] ${
            isDark ? "border-slate-700/80" : "border-blue-100"
          }`}
        >
          <div className="flex items-center gap-2">
            <FiLayers className={`text-sm shrink-0 ${isDark ? "text-blue-400" : "text-blue-600"}`} />
            <span className={isDark ? "text-slate-300 font-medium" : "text-slate-600 font-medium"}>
              Correlated Events:
            </span>
            <strong className={`font-mono font-bold ${isDark ? "text-slate-100" : "text-slate-900"}`}>
              {relatedCount}
            </strong>
          </div>
          <div className="flex items-center gap-2">
            <FiClock className={`text-sm shrink-0 ${isDark ? "text-blue-400" : "text-blue-600"}`} />
            <span className={isDark ? "text-slate-300 font-medium" : "text-slate-600 font-medium"}>
              Sliding Window:
            </span>
            <strong className={`font-mono font-bold ${isDark ? "text-slate-100" : "text-slate-900"}`}>
              {timeWindow}m
            </strong>
          </div>
          <div className="flex items-center gap-2">
            <FiGitCommit className={`text-sm shrink-0 ${isDark ? "text-purple-400" : "text-purple-600"}`} />
            <span className={isDark ? "text-slate-300 font-medium" : "text-slate-600 font-medium"}>
              Attack Chain:
            </span>
            <strong className={`truncate font-bold ${isDark ? "text-purple-300" : "text-purple-700"}`}>
              {chainDetected ? chainType : "None"}
            </strong>
          </div>
          <div className="flex items-center gap-2">
            <FiKey className={`text-sm shrink-0 ${isDark ? "text-blue-400" : "text-blue-600"}`} />
            <span className={isDark ? "text-slate-300 font-medium" : "text-slate-600 font-medium"}>
              Pivots:
            </span>
            <strong className={`truncate font-bold ${isDark ? "text-slate-100" : "text-slate-900"}`}>
              {correlationKeys.join(", ")}
            </strong>
          </div>
        </div>
      </div>
    </div>
  );
}
