import React from "react";
import { FiCheckSquare, FiAlertCircle, FiShield } from "react-icons/fi";
import { PriorityBadge } from "./RiskBadge";

export default function RecommendationsPanel({ recommendations = [] }) {
  if (!recommendations || recommendations.length === 0) {
    return (
      <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-6 text-center space-y-2">
        <div className="flex justify-center">
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-slate-800 text-slate-400">
            <FiCheckSquare className="text-xl" />
          </div>
        </div>
        <h4 className="text-sm font-semibold text-slate-300">No Advisory Recommendations Available</h4>
        <p className="text-xs text-slate-400">No specific action items generated for this threat classification.</p>
      </div>
    );
  }

  return (
    <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-5 md:p-6 space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#1F2937] pb-4">
        <div className="space-y-0.5">
          <div className="flex items-center gap-2">
            <FiShield className="text-blue-400 text-base" />
            <h3 className="text-base font-bold text-slate-100">Advisory Response Recommendations</h3>
          </div>
          <p className="text-xs text-slate-400">
            Tailored SOC guidance & recommended analyst actions (Advisory-only; non-destructive)
          </p>
        </div>
        <span className="text-xs font-semibold px-2.5 py-1 rounded-md bg-blue-500/10 text-blue-300 border border-blue-500/20">
          {recommendations.length} Recommended Actions
        </span>
      </div>

      {/* Recommendations List */}
      <div className="space-y-3">
        {recommendations.map((rec, idx) => (
          <div
            key={idx}
            className="bg-[#1E293B] border border-[#1F2937] rounded-lg p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:border-slate-600 transition-colors"
          >
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="flex h-5 w-5 items-center justify-center rounded-full bg-[#111827] text-blue-400 text-[11px] font-bold shrink-0 border border-[#1F2937]">
                  {idx + 1}
                </span>
                <h4 className="text-xs sm:text-sm font-bold text-slate-100">{rec.action}</h4>
              </div>
              <p className="text-xs text-slate-400 pl-7">{rec.reason}</p>
            </div>

            <div className="shrink-0 pl-7 sm:pl-0">
              <PriorityBadge priority={rec.priority} size="sm" />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
