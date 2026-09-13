import { Line } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend,
  Filler,
} from "chart.js";
import { useTheme } from "../context/ThemeContext";

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend, Filler);

export default function ThreatTrendChart({ trendData = [] }) {
  const { isDark } = useTheme();

  // trendData is pre-aggregated from backend: [{date: "YYYY-MM-DD", count, suspicious, critical, normal}, ...]
  const labels = trendData.map((d) => {
    const dateObj = new Date(d.date + "T00:00:00");
    return dateObj.toLocaleDateString("en-US", { month: "short", day: "2-digit" });
  });

  const suspiciousCounts = trendData.map((d) => d.suspicious ?? 0);
  const criticalCounts = trendData.map((d) => d.critical ?? 0);

  const data = {
    labels,
    datasets: [
      {
        label: "Suspicious Predictions",
        data: suspiciousCounts,
        borderColor: "#F59E0B",
        backgroundColor: "rgba(245, 158, 11, 0.12)",
        fill: true,
        tension: 0.35,
        pointRadius: 3,
        pointHoverRadius: 5,
        pointBackgroundColor: "#F59E0B",
      },
      {
        label: "Critical Threats",
        data: criticalCounts,
        borderColor: "#EF4444",
        backgroundColor: "rgba(239, 68, 68, 0.12)",
        fill: true,
        tension: 0.35,
        pointRadius: 3,
        pointHoverRadius: 5,
        pointBackgroundColor: "#EF4444",
      },
    ],
  };

  const options = {
    plugins: {
      legend: {
        position: "top",
        align: "end",
        labels: { boxWidth: 10, color: isDark ? "#94A3B8" : "#475569", font: { size: 10, weight: 600 } },
      },
      tooltip: {
        backgroundColor: isDark ? "#0B1329" : "#FFFFFF",
        titleColor: isDark ? "#F8FAFC" : "#0F172A",
        bodyColor: isDark ? "#CBD5E1" : "#334155",
        borderColor: isDark ? "#1F2937" : "#CBD5E1",
        borderWidth: 1,
        callbacks: {
          label: (context) => ` ${context.dataset.label}: ${context.raw.toLocaleString()}`,
        },
      },
    },
    scales: {
      x: {
        ticks: { font: { size: 10 }, color: isDark ? "#94A3B8" : "#475569", maxRotation: 0, autoSkip: true },
        grid: { color: isDark ? "#1E293B" : "#E2E8F0" },
      },
      y: {
        beginAtZero: true,
        ticks: { font: { size: 10 }, color: isDark ? "#94A3B8" : "#475569", precision: 0 },
        grid: { color: isDark ? "#1E293B" : "#E2E8F0" },
      },
    },
    maintainAspectRatio: false,
  };

  return (
    <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 md:p-5 shadow-sm h-full flex flex-col hover:border-slate-700 transition-all duration-200">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-bold text-slate-100">Threat Trend Over Time</h3>
        <span className="text-xs font-mono font-medium text-purple-400 bg-purple-500/10 px-2 py-0.5 rounded border border-purple-500/20">
          Historical M2 Evaluation
        </span>
      </div>
      <div className="flex-1 min-h-[240px] md:min-h-[260px]">
        {labels.length === 0 ? (
          <div className="h-full flex items-center justify-center text-xs text-slate-500">
            No trend data available
          </div>
        ) : (
          <Line data={data} options={options} />
        )}
      </div>
    </div>
  );
}
