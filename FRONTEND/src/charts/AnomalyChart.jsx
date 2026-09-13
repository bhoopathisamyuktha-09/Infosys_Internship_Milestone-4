import { Pie } from "react-chartjs-2";
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from "chart.js";
import { useTheme } from "../context/ThemeContext";

ChartJS.register(ArcElement, Tooltip, Legend);

const COLORS = {
  Normal: "#10B981",
  Suspicious: "#F59E0B",
  Critical: "#EF4444",
};

export default function AnomalyChart({ distStats = {} }) {
  const { isDark } = useTheme();

  // Use aggregate stats from /model-performance backend endpoint
  const totalPreds = distStats.total_predictions ?? 0;
  const criticalCount = distStats.critical_count ?? 0;
  const suspiciousCount = distStats.suspicious_count ?? 0;
  const normalCount = distStats.normal_count ?? (totalPreds - suspiciousCount - criticalCount);
  const anomalyCount = distStats.anomaly_count ?? 0;

  const total = totalPreds > 0 ? totalPreds : normalCount + suspiciousCount + criticalCount;
  const highRiskPct = total > 0 ? (((suspiciousCount + criticalCount) / total) * 100).toFixed(1) : "0.0";

  const data = {
    labels: ["Normal Verdict", "Suspicious Verdict", "Critical Verdict"],
    datasets: [
      {
        data: [normalCount, suspiciousCount, criticalCount],
        backgroundColor: [COLORS.Normal, COLORS.Suspicious, COLORS.Critical],
        borderWidth: 0,
      },
    ],
  };

  const options = {
    plugins: {
      legend: {
        position: "bottom",
        labels: {
          boxWidth: 12,
          color: isDark ? "#94A3B8" : "#475569",
          font: { size: 11, weight: 600 },
        },
      },
      tooltip: {
        backgroundColor: isDark ? "#0B1329" : "#FFFFFF",
        titleColor: isDark ? "#F8FAFC" : "#0F172A",
        bodyColor: isDark ? "#CBD5E1" : "#334155",
        borderColor: isDark ? "#1F2937" : "#CBD5E1",
        borderWidth: 1,
        callbacks: {
          label: (context) => {
            const val = context.raw || 0;
            const pct = total > 0 ? ((val / total) * 100).toFixed(1) : 0;
            return ` ${context.label}: ${val.toLocaleString()} (${pct}%)`;
          },
        },
      },
    },
    maintainAspectRatio: false,
  };

  return (
    <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 md:p-5 shadow-sm h-full flex flex-col hover:border-slate-700 transition-all duration-200">
      <div className="flex items-center justify-between mb-3">
        <div>
          <h3 className="text-sm font-bold text-slate-100">Hybrid Threat Distribution</h3>
          <p className="text-[11px] text-slate-400">IF Anomalies: <strong className="text-amber-400">{anomalyCount.toLocaleString()}</strong> ({((anomalyCount / (total || 1)) * 100).toFixed(1)}%)</p>
        </div>
        <span className="text-xs font-semibold px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20">
          {highRiskPct}% Elevated
        </span>
      </div>
      <div className="flex-1 min-h-[240px] md:min-h-[260px]">
        {total === 0 ? (
          <div className="h-full flex items-center justify-center text-xs text-slate-500">
            No prediction data available
          </div>
        ) : (
          <Pie data={data} options={options} />
        )}
      </div>
    </div>
  );
}
