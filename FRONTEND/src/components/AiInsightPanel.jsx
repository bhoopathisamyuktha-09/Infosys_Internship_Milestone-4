import { BrainCircuit, Target, ShieldAlert } from "lucide-react";
import { Link } from "react-router-dom";

const VERDICT_DOT = {
  Critical: "bg-red-500",
  Suspicious: "bg-amber-500",
  Normal: "bg-emerald-500",
};

export default function AiInsightPanel({ insights, avgRiskScore, m2Summary = [], m2Perf = null, topPredictions = [] }) {
  // If M2 model performance data is available, compute data-driven M2 summary
  const distStats = m2Perf?.prediction_distribution_stats;
  const hasM2Data = Boolean(distStats && m2Summary.length > 0);

  // Compute top 3 threat categories from m2Summary
  const topThreatTypes = hasM2Data
    ? [...m2Summary].sort((a, b) => (b.count || 0) - (a.count || 0)).slice(0, 3)
    : [];

  const topCategoryName = topThreatTypes[0]?.threat_type || "Unknown";
  const topCategoryPct = topThreatTypes[0]?.percentage !== undefined ? `${topThreatTypes[0].percentage}%` : "";

  const totalEvaluated = distStats?.total_predictions ?? 0;
  const totalAnomalies = distStats?.anomaly_count ?? 0;
  const totalCritical = distStats?.critical_count ?? 0;
  const avgConfidence = distStats?.average_confidence !== undefined ? distStats.average_confidence.toFixed(1) : "0.0";

  const m2SummaryText = `${totalEvaluated.toLocaleString()} security events evaluated by the Milestone 2 AI Threat Detection Engine, identifying ${totalAnomalies.toLocaleString()} Isolation Forest anomalies and ${totalCritical.toLocaleString()} Critical hybrid threat verdicts. Most frequent predicted threat category: ${topCategoryName} (${topCategoryPct}).`;

  return (
    <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 md:p-5 shadow-sm text-slate-100 hover:border-slate-700 transition-all duration-200">
      <div className="flex items-center justify-between mb-3 border-b border-[#1F2937] pb-3">
        <div className="flex items-center gap-2">
          <BrainCircuit className="w-5 h-5 text-blue-400" />
          <h3 className="text-sm font-bold text-slate-100">AI Threat Detection Summary</h3>
        </div>
        <div className="text-right flex items-center gap-2">
          <span className="text-xs uppercase tracking-wider font-semibold text-slate-400">
            {hasM2Data ? "Avg Hybrid Confidence:" : "Avg Risk Score:"}
          </span>
          <span className="text-xl font-extrabold text-blue-400 font-mono">
            {hasM2Data ? `${avgConfidence}%` : `${avgRiskScore}%`}
          </span>
        </div>
      </div>

      <p className="text-xs md:text-sm text-slate-300 leading-relaxed mb-4">
        {hasM2Data ? m2SummaryText : insights?.summary}
      </p>

      <div className="grid gap-4 sm:grid-cols-2">
        {/* Most Frequent Predicted Threat Types */}
        <div>
          <p className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-2">
            Most Frequent Predicted Threat Types
          </p>
          <div className="space-y-1.5">
            {hasM2Data
              ? topThreatTypes.map((t) => (
                  <div key={t.threat_type} className="flex items-center justify-between bg-[#0B1329] border border-[#1F2937] rounded-lg px-3 py-1.5">
                    <div className="flex items-center gap-2 min-w-0">
                      <Target className="w-3.5 h-3.5 text-blue-400 shrink-0" />
                      <span className="text-xs text-slate-300 truncate font-medium">{t.threat_type}</span>
                    </div>
                    <span className="text-xs font-mono font-bold text-blue-400 shrink-0 ml-2">
                      {t.count?.toLocaleString()} ({t.percentage !== undefined ? `${t.percentage}%` : ""})
                    </span>
                  </div>
                ))
              : (insights?.topTechniques || []).map((t) => (
                  <div key={t.id} className="flex items-center justify-between bg-[#0B1329] border border-[#1F2937] rounded-lg px-3 py-1.5">
                    <div className="flex items-center gap-2 min-w-0">
                      <Target className="w-3.5 h-3.5 text-blue-400 shrink-0" />
                      <span className="text-xs text-slate-300 truncate font-medium" title={t.technique}>{t.technique}</span>
                    </div>
                    <span className="text-xs font-mono font-bold text-slate-400 shrink-0 ml-2">
                      {t.id} · {t.count}
                    </span>
                  </div>
                ))}
          </div>
        </div>

        {/* Highest Risk Predictions */}
        <div>
          <p className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-2">
            Highest Risk Predictions (M2 Evaluated)
          </p>
          <div className="space-y-1.5">
            {topPredictions.length > 0
              ? topPredictions.slice(0, 3).map((p) => (
                  <div key={p.prediction_id || p.event_id} className="flex items-center justify-between bg-[#0B1329] border border-[#1F2937] rounded-lg px-3 py-1.5">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className={`w-2 h-2 rounded-full shrink-0 ${VERDICT_DOT[p.verdict] || "bg-blue-500"}`} />
                      <Link to={`/dashboard/events/${encodeURIComponent(p.prediction_id || p.event_id)}`} className="text-xs text-blue-400 hover:underline truncate font-mono font-bold">
                        {p.event_id}
                      </Link>
                      <span className="text-xs text-slate-400 truncate">{p.predicted_threat_type}</span>
                    </div>
                    <span className="text-xs font-mono font-bold text-red-400 shrink-0 ml-2">
                      {p.confidence_score?.toFixed(1)}%
                    </span>
                  </div>
                ))
              : (insights?.topRiskEvents || []).map((e) => (
                  <div key={e.id} className="flex items-center justify-between bg-[#0B1329] border border-[#1F2937] rounded-lg px-3 py-1.5">
                    <div className="flex items-center gap-2 min-w-0">
                      <ShieldAlert className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                      <span className="text-xs text-slate-300 truncate font-medium">{e.eventType}</span>
                    </div>
                    <span className="text-xs font-mono font-bold text-blue-400 shrink-0 ml-2">
                      {e.riskScore}%
                    </span>
                  </div>
                ))}
          </div>
        </div>
      </div>
    </div>
  );
}
