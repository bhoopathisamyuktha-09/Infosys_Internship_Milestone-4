import React from "react";
import { FiCheckCircle, FiClock, FiUser, FiMessageSquare, FiInfo } from "react-icons/fi";

export default function AnalystFeedbackCard({ feedbackList }) {
  if (!feedbackList || !feedbackList.length) return null;

  return (
    <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-5 md:p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-[#1F2937] pb-3">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-amber-500/15 text-amber-400 border border-amber-500/30">
            <FiCheckCircle className="text-base" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-100">Analyst False Positive Review</h3>
            <p className="text-xs text-slate-400">Audit history and rationale recorded by SOC analysts</p>
          </div>
        </div>

        <span className="text-[11px] font-semibold px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
          {feedbackList.length} Review{feedbackList.length > 1 ? "s" : ""} Logged
        </span>
      </div>

      {/* Reviews List */}
      <div className="space-y-3">
        {feedbackList.map((item, idx) => (
          <div
            key={item.feedback_id || idx}
            className="bg-[#1E293B]/70 border border-[#1F2937] rounded-xl p-4 space-y-2.5"
          >
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs font-bold px-2.5 py-1 rounded bg-amber-500/15 text-amber-300 border border-amber-500/30">
                  {item.reason}
                </span>
                <span className="text-xs text-slate-400 flex items-center gap-1 font-medium">
                  <FiUser className="text-slate-500 text-xs" />
                  Reviewed by <strong className="text-slate-200">{item.analyst || "SOC Analyst"}</strong>
                </span>
              </div>

              <div className="flex items-center gap-1.5 text-[11px] text-slate-400 font-mono">
                <FiClock className="text-xs" />
                <span>{item.created_at}</span>
              </div>
            </div>

            {item.comment ? (
              <div className="text-xs text-slate-300 p-2.5 rounded-lg bg-[#0F172A] border border-[#1E293B] flex items-start gap-2">
                <FiMessageSquare className="text-slate-500 text-xs mt-0.5 shrink-0" />
                <p className="leading-relaxed">{item.comment}</p>
              </div>
            ) : (
              <p className="text-[11px] text-slate-500 italic">No additional notes provided.</p>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
