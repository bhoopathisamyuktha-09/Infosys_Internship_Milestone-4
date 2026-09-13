import React, { useState } from "react";
import { Link } from "react-router-dom";
import {
  FiGitCommit,
  FiFilter,
  FiArrowRight,
  FiClock,
  FiServer,
  FiRefreshCw,
} from "react-icons/fi";

import ErrorBanner from "../../components/ErrorBanner";
import { RiskLevelBadge, PriorityBadge, RiskScoreBadge } from "../../components/m3/RiskBadge";
import AttackChainTimeline from "../../components/m3/AttackChainTimeline";
import { getAttackChains } from "../../services/api";
import { useAsyncData } from "../../hooks/useAsyncData";

const CHAIN_TYPES = [
  "All",
  "Privilege Escalation Chain",
  "Brute Force Chain",
  "Data Exfiltration Chain",
];

export default function AttackChains() {
  const [selectedType, setSelectedType] = useState("All");

  const { data, loading, error, reload } = useAsyncData(async () => {
    const res = await getAttackChains({ limit: 50 });
    return res.items || [];
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="flex items-center gap-3 text-slate-400 text-sm">
          <span className="h-2 w-2 rounded-full bg-purple-500 animate-ping"></span>
          <span>Analyzing multi-stage attack chains...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return <ErrorBanner message={error} onRetry={reload} />;
  }

  const allChains = data || [];
  const filteredChains =
    selectedType === "All"
      ? allChains
      : allChains.filter((c) => c.attack_chain_type === selectedType);

  return (
    <div className="grid gap-5 md:gap-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#111827] border border-[#1F2937] rounded-xl p-4 md:p-5">
        <div>
          <div className="flex items-center gap-2">
            <FiGitCommit className="text-purple-400 text-xl" />
            <h2 className="text-lg md:text-xl font-bold text-slate-100">Multi-Stage Attack Chains</h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Reconstructed chronological adversary progression across Initial Access, Escalation, Discovery & Execution
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={reload}
            disabled={loading}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[#1F2937] bg-[#1E293B] hover:bg-slate-700 text-xs font-semibold text-slate-300 transition-colors"
          >
            <FiRefreshCw className={loading ? "animate-spin" : ""} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Executive Explainer Banner */}
      <div className="bg-purple-500/10 border border-purple-500/25 rounded-xl px-4 py-3 text-xs flex items-center justify-between gap-3 text-purple-200">
        <div className="flex items-center gap-2">
          <FiGitCommit className="text-purple-400 shrink-0 text-sm" />
          <span>
            <strong>Executive Overview:</strong> This view correlates multiple security events into a chronological attack progression.
          </span>
        </div>
        <span className="hidden md:inline-block text-[10px] font-mono text-purple-300 bg-purple-500/20 px-2 py-0.5 rounded border border-purple-500/30 shrink-0 font-bold">
          CHRONOLOGICAL CORRELATION
        </span>
      </div>

      {/* Filter Chips Bar */}
      <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-bold uppercase tracking-wider text-slate-400 mr-1 flex items-center gap-1">
            <FiFilter className="text-xs" />
            <span>Chain Type:</span>
          </span>
          {CHAIN_TYPES.map((type) => (
            <button
              key={type}
              onClick={() => setSelectedType(type)}
              className={`px-3 py-1 rounded-lg text-xs font-semibold transition-colors cursor-pointer ${
                selectedType === type
                  ? "bg-purple-600 text-white shadow-md"
                  : "bg-[#1E293B] text-slate-300 hover:bg-slate-700 hover:text-white border border-[#1F2937]"
              }`}
            >
              {type}
            </button>
          ))}
        </div>

        <span className="text-xs text-slate-400 font-mono">
          Showing <strong className="text-slate-100">{filteredChains.length}</strong> of {allChains.length} Attack Chains
        </span>
      </div>

      {/* Attack Chains List */}
      {filteredChains.length === 0 ? (
        <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-12 text-center space-y-2">
          <FiGitCommit className="text-3xl text-slate-500 mx-auto" />
          <h4 className="text-sm font-semibold text-slate-300">No Attack Chains Match Filter</h4>
          <p className="text-xs text-slate-400 max-w-sm mx-auto">
            Try selecting "All" or choosing another chain type filter.
          </p>
        </div>
      ) : (
        <div className="space-y-6">
          {filteredChains.map((chainDoc) => (
            <div
              key={chainDoc.incident_id}
              className="bg-[#111827] border border-[#1F2937] rounded-xl p-5 md:p-6 space-y-4 shadow-sm"
            >
              {/* Chain Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#1F2937] pb-4">
                <div className="flex items-center gap-3">
                  <RiskScoreBadge score={chainDoc.risk_score} level={chainDoc.risk_level} size="md" />
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <Link
                        to={`/dashboard/incidents/${chainDoc.incident_id}`}
                        className="font-mono text-sm font-bold text-blue-400 hover:underline"
                      >
                        {chainDoc.incident_id}
                      </Link>
                      <span className="text-sm font-bold text-slate-100">{chainDoc.threat_type}</span>
                      <RiskLevelBadge level={chainDoc.risk_level} size="sm" />
                      <PriorityBadge priority={chainDoc.priority} size="sm" />
                    </div>
                    <div className="flex items-center gap-4 text-xs text-slate-400 mt-1 font-mono">
                      <span className="flex items-center gap-1">
                        <FiServer className="text-slate-500" />
                        Asset: <strong className="text-slate-200">{chainDoc.asset_name || "Unknown"}</strong>
                      </span>
                      <span className="flex items-center gap-1">
                        <FiClock className="text-slate-500" />
                        {chainDoc.created_at || "N/A"}
                      </span>
                    </div>
                  </div>
                </div>

                <Link
                  to={`/dashboard/incidents/${chainDoc.incident_id}`}
                  className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-md bg-blue-600 hover:bg-blue-700 text-white font-semibold shadow-xs transition-colors text-xs shrink-0 self-start sm:self-center"
                >
                  <span>Investigate Incident</span>
                  <FiArrowRight />
                </Link>
              </div>

              {/* Embedded Timeline */}
              {chainDoc.attack_chain && (
                <AttackChainTimeline attackChain={chainDoc.attack_chain} />
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
