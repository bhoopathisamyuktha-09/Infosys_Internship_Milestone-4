import React, { useState, useEffect } from "react";
import {
  FiSliders,
  FiX,
  FiRotateCcw,
  FiCheck,
  FiAlertTriangle,
  FiInfo,
  FiCheckCircle,
} from "react-icons/fi";
import { getRiskWeights, updateRiskWeights, resetRiskWeights } from "../../services/api";

const FACTOR_METADATA = [
  {
    key: "threat_severity",
    label: "Threat Severity",
    defaultPct: 25,
    desc: "Baseline severity assigned to the classified threat type (0-100 normalized).",
  },
  {
    key: "ml_confidence",
    label: "ML Model Confidence",
    defaultPct: 25,
    desc: "Machine learning classifier prediction confidence score.",
  },
  {
    key: "asset_criticality",
    label: "Asset Criticality",
    defaultPct: 20,
    desc: "Business value and criticality rating of the targeted asset (e.g. Critical, High).",
  },
  {
    key: "vulnerability_cvss",
    label: "Vulnerability CVSS",
    defaultPct: 20,
    desc: "Common Vulnerability Scoring System severity score for correlated CVEs.",
  },
  {
    key: "threat_intelligence",
    label: "Threat Intelligence",
    defaultPct: 10,
    desc: "Known indicator of compromise (IOC) confidence and actor match in threat intel feeds.",
  },
];

export default function RiskWeightConfigModal({ isOpen, onClose, onWeightsSaved }) {
  const [weights, setWeights] = useState({
    threat_severity: 25,
    ml_confidence: 25,
    asset_criticality: 20,
    vulnerability_cvss: 20,
    threat_intelligence: 10,
  });

  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  useEffect(() => {
    if (isOpen) {
      loadWeights();
    }
  }, [isOpen]);

  async function loadWeights() {
    setLoading(true);
    setError(null);
    try {
      const data = await getRiskWeights();
      setWeights({
        threat_severity: Math.round((data.threat_severity ?? 0.25) * 100),
        ml_confidence: Math.round((data.ml_confidence ?? 0.25) * 100),
        asset_criticality: Math.round((data.asset_criticality ?? 0.2) * 100),
        vulnerability_cvss: Math.round((data.vulnerability_cvss ?? 0.2) * 100),
        threat_intelligence: Math.round((data.threat_intelligence ?? 0.1) * 100),
      });
    } catch (err) {
      setError(err.message || "Failed to load current risk weights.");
    } finally {
      setLoading(false);
    }
  }

  function handleSliderChange(key, value) {
    const parsed = parseInt(value, 10);
    const num = Math.max(0, Math.min(100, isNaN(parsed) ? 0 : parsed));
    setWeights((prev) => ({ ...prev, [key]: num }));
  }

  const total =
    (weights.threat_severity ?? 0) +
    (weights.ml_confidence ?? 0) +
    (weights.asset_criticality ?? 0) +
    (weights.vulnerability_cvss ?? 0) +
    (weights.threat_intelligence ?? 0);

  const isValid = total === 100;

  async function handleSave() {
    if (!isValid) return;
    setSaving(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const payload = {
        threat_severity: Number(((weights.threat_severity ?? 0) / 100).toFixed(4)),
        ml_confidence: Number(((weights.ml_confidence ?? 0) / 100).toFixed(4)),
        asset_criticality: Number(((weights.asset_criticality ?? 0) / 100).toFixed(4)),
        vulnerability_cvss: Number(((weights.vulnerability_cvss ?? 0) / 100).toFixed(4)),
        threat_intelligence: Number(((weights.threat_intelligence ?? 0) / 100).toFixed(4)),
      };
      await updateRiskWeights(payload);
      setSuccessMsg("Risk weights successfully updated. New calculations will use these weights.");
      if (onWeightsSaved) onWeightsSaved(payload);
      setTimeout(() => {
        setSuccessMsg(null);
        onClose();
      }, 1500);
    } catch (err) {
      setError(err.message || "Failed to save risk weights.");
    } finally {
      setSaving(false);
    }
  }

  async function handleReset() {
    setSaving(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const data = await resetRiskWeights();
      setWeights({
        threat_severity: Math.round((data.threat_severity ?? 0.25) * 100),
        ml_confidence: Math.round((data.ml_confidence ?? 0.25) * 100),
        asset_criticality: Math.round((data.asset_criticality ?? 0.2) * 100),
        vulnerability_cvss: Math.round((data.vulnerability_cvss ?? 0.2) * 100),
        threat_intelligence: Math.round((data.threat_intelligence ?? 0.1) * 100),
      });
      setSuccessMsg("Restored default risk weights (25%, 25%, 20%, 20%, 10%).");
      if (onWeightsSaved) onWeightsSaved(data);
      setTimeout(() => setSuccessMsg(null), 2500);
    } catch (err) {
      setError(err.message || "Failed to reset risk weights.");
    } finally {
      setSaving(false);
    }
  }

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xs">
      <div className="relative w-full max-w-xl rounded-2xl bg-[#0F172A] border border-[#1E293B] shadow-2xl text-slate-100 overflow-hidden animate-in fade-in zoom-in-95 duration-200">
        {/* Modal Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1E293B] bg-[#111827]">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-blue-500/15 text-blue-400 border border-blue-500/30">
              <FiSliders className="text-base" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-100">Dynamic Risk Weight Configuration</h3>
              <p className="text-xs text-slate-400">Configure factor distribution for the 5-factor risk engine</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-[#1E293B] transition-colors"
          >
            <FiX className="text-lg" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-5 max-h-[75vh] overflow-y-auto">
          {/* Important SOC Notice */}
          <div className="flex items-start gap-3 p-3 rounded-xl bg-blue-950/40 border border-blue-500/30 text-xs text-blue-200">
            <FiInfo className="text-blue-400 text-sm mt-0.5 shrink-0" />
            <div>
              <span className="font-semibold text-blue-300">Operational Notice: </span>
              Updating weights takes effect dynamically for all <em>subsequent</em> risk assessments and incident evaluations. Existing incident records remain immutable to preserve investigation audit integrity.
            </div>
          </div>

          {/* Error / Success Banners */}
          {error && (
            <div className="p-3 rounded-xl bg-red-500/15 border border-red-500/30 text-xs text-red-300 flex items-center gap-2">
              <FiAlertTriangle className="text-red-400 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {successMsg && (
            <div className="p-3 rounded-xl bg-emerald-500/15 border border-emerald-500/30 text-xs text-emerald-300 flex items-center gap-2">
              <FiCheckCircle className="text-emerald-400 shrink-0" />
              <span>{successMsg}</span>
            </div>
          )}

          {/* Factor Controls */}
          {loading ? (
            <div className="py-12 flex flex-col items-center justify-center space-y-2 text-slate-400 text-xs">
              <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
              <span>Retrieving active weights from backend...</span>
            </div>
          ) : (
            <div className="space-y-4">
              {FACTOR_METADATA.map((factor) => {
                const currentVal = weights[factor.key] ?? 0;
                return (
                  <div
                    key={factor.key}
                    className="p-3.5 rounded-xl bg-[#1E293B]/70 border border-[#334155]/60 space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <span className="text-xs font-bold text-slate-200 block">{factor.label}</span>
                        <span className="text-[11px] text-slate-400 leading-tight block">{factor.desc}</span>
                      </div>
                      <div className="flex items-center gap-1 shrink-0 pl-3">
                        <input
                          type="number"
                          min="0"
                          max="100"
                          value={currentVal}
                          onChange={(e) => handleSliderChange(factor.key, e.target.value)}
                          className="w-14 rounded-md bg-[#0F172A] border border-[#334155] px-2 py-1 text-right text-xs font-mono font-bold text-slate-100 focus:outline-none focus:border-blue-500"
                        />
                        <span className="text-xs text-slate-400 font-bold">%</span>
                      </div>
                    </div>

                    {/* Range Slider */}
                    <div className="pt-1">
                      <input
                        type="range"
                        min="0"
                        max="100"
                        value={currentVal}
                        onChange={(e) => handleSliderChange(factor.key, e.target.value)}
                        className="w-full accent-blue-500 cursor-pointer bg-slate-700 h-1.5 rounded-lg"
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Live Total Indicator */}
          <div className="flex items-center justify-between p-3.5 rounded-xl bg-[#111827] border border-[#1E293B]">
            <div className="space-y-0.5">
              <span className="text-xs font-bold text-slate-300 block">Total Percentage Allocation</span>
              <span className="text-[11px] text-slate-400">
                {isValid
                  ? "Weights sum to exactly 100%. Ready to apply."
                  : `Total must equal 100% (currently ${total}% - ${total > 100 ? "exceeds by " + (total - 100) : "short by " + (100 - total)}%)`}
              </span>
            </div>

            <div
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-extrabold flex items-center gap-1.5 border ${
                isValid
                  ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/40"
                  : "bg-red-500/20 text-red-300 border-red-500/40"
              }`}
            >
              <span>{total}%</span>
              {isValid ? <FiCheck className="text-sm" /> : <FiAlertTriangle className="text-sm" />}
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="flex items-center justify-between px-6 py-4 border-t border-[#1E293B] bg-[#111827]">
          <button
            type="button"
            onClick={handleReset}
            disabled={saving || loading}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-300 bg-[#1E293B] hover:bg-slate-700 border border-[#334155] transition-colors disabled:opacity-50"
          >
            <FiRotateCcw className="text-xs" />
            <span>Reset to Defaults</span>
          </button>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              disabled={saving}
              className="px-4 py-1.5 rounded-lg text-xs font-semibold text-slate-400 hover:text-slate-200 hover:bg-[#1E293B] transition-colors"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleSave}
              disabled={!isValid || saving || loading}
              className="inline-flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs font-bold text-white bg-blue-600 hover:bg-blue-500 transition-colors shadow-md shadow-blue-900/40 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {saving ? (
                <>
                  <span className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  <span>Saving...</span>
                </>
              ) : (
                <>
                  <FiCheck />
                  <span>Save Configuration</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
