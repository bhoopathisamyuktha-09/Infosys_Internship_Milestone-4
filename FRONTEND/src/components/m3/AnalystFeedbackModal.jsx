import React, { useState } from "react";
import {
  FiAlertCircle,
  FiX,
  FiCheck,
  FiInfo,
  FiMessageSquare,
  FiUserCheck,
} from "react-icons/fi";
import { FEEDBACK_REASONS, submitAnalystFeedback } from "../../services/api";

export default function AnalystFeedbackModal({
  isOpen,
  incidentId,
  onClose,
  onFeedbackSubmitted,
}) {
  const [reason, setReason] = useState(FEEDBACK_REASONS[0]);
  const [comment, setComment] = useState("");
  const [analystName, setAnalystName] = useState("SOC Analyst");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);

  if (!isOpen) return null;

  async function handleSubmit(e) {
    e.preventDefault();
    if (!reason) {
      setError("Please select a valid feedback reason.");
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      const record = await submitAnalystFeedback(incidentId, {
        reason,
        comment: comment.trim() || undefined,
        analyst: analystName.trim() || "SOC Analyst",
      });
      if (onFeedbackSubmitted) {
        onFeedbackSubmitted(record);
      }
      onClose();
    } catch (err) {
      setError(err.message || "Failed to submit analyst feedback.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xs">
      <div className="relative w-full max-w-lg rounded-2xl bg-[#0F172A] border border-[#1E293B] shadow-2xl text-slate-100 overflow-hidden animate-in fade-in zoom-in-95 duration-200">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1E293B] bg-[#111827]">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-amber-500/15 text-amber-400 border border-amber-500/30">
              <FiAlertCircle className="text-base" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-100">False Positive Analyst Feedback</h3>
              <p className="text-xs text-slate-400">
                Categorize rationale for marking <span className="font-mono text-blue-400 font-bold">{incidentId}</span> as False Positive
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-[#1E293B] transition-colors"
          >
            <FiX className="text-lg" />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit}>
          <div className="p-6 space-y-4">
            {/* Notice */}
            <div className="flex items-start gap-2.5 p-3 rounded-xl bg-slate-900 border border-[#1E293B] text-xs text-slate-300">
              <FiInfo className="text-blue-400 text-sm mt-0.5 shrink-0" />
              <div>
                <span className="font-semibold text-slate-200">Audit & Model Tuning: </span>
                Feedback is captured to inform future security tuning and compliance audits. This action marks the incident as False Positive and stores an immutable analyst audit record.
              </div>
            </div>

            {error && (
              <div className="p-3 rounded-xl bg-red-500/15 border border-red-500/30 text-xs text-red-300 flex items-center gap-2">
                <FiAlertCircle className="text-red-400 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {/* Mandatory Reason */}
            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-200 block">
                False Positive Reason <span className="text-red-400">*</span>
              </label>
              <select
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                className="w-full rounded-lg bg-[#1E293B] border border-[#334155] px-3 py-2 text-xs font-semibold text-slate-100 focus:outline-none focus:border-blue-500 cursor-pointer"
                required
              >
                {FEEDBACK_REASONS.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
            </div>

            {/* Optional Analyst Notes */}
            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-200 flex items-center justify-between">
                <span>Analyst Notes / Context</span>
                <span className="text-[11px] font-normal text-slate-400">Optional</span>
              </label>
              <textarea
                value={comment}
                onChange={(e) => setComment(e.target.value)}
                maxLength={1000}
                rows={3}
                placeholder="Provide specific investigation details (e.g. ticket number, authorized maintenance window, test scanner IP)..."
                className="w-full rounded-lg bg-[#1E293B] border border-[#334155] p-3 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-blue-500 resize-none"
              />
            </div>

            {/* Analyst Identifier */}
            <div className="space-y-1.5">
              <label className="text-xs font-bold text-slate-200 block">Reviewing Analyst</label>
              <input
                type="text"
                value={analystName}
                onChange={(e) => setAnalystName(e.target.value)}
                className="w-full rounded-lg bg-[#1E293B] border border-[#334155] px-3 py-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>

          {/* Footer */}
          <div className="flex items-center justify-end gap-2.5 px-6 py-4 border-t border-[#1E293B] bg-[#111827]">
            <button
              type="button"
              onClick={onClose}
              disabled={submitting}
              className="px-4 py-1.5 rounded-lg text-xs font-semibold text-slate-400 hover:text-slate-200 hover:bg-[#1E293B] transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting || !reason}
              className="inline-flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs font-bold text-white bg-amber-600 hover:bg-amber-500 transition-colors shadow-md shadow-amber-900/30 disabled:opacity-50"
            >
              {submitting ? (
                <>
                  <span className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  <span>Submitting...</span>
                </>
              ) : (
                <>
                  <FiCheck />
                  <span>Confirm False Positive</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
