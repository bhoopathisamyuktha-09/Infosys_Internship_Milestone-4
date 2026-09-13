import { Bar } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Tooltip,
  Legend,
} from "chart.js";
import { useTheme } from "../context/ThemeContext";

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip, Legend);

export default function ThreatTypeChart({ summary = [] }) {
  const { isDark } = useTheme();
  const sorted = [...summary].sort((a, b) => b.count - a.count).slice(0, 8);

  const labels = sorted.map((s) => s.threat_type || "Unknown");
  const counts = sorted.map((s) => s.count || 0);

  const data = {
    labels,
    datasets: [
      {
        label: "Predictions Count",
        data: counts,
        backgroundColor: "#3B82F6",
        borderRadius: 6,
        maxBarThickness: 24,
      },
    ],
  };

  const options = {
    indexAxis: "y",
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: isDark ? "#0B1329" : "#FFFFFF",
        titleColor: isDark ? "#F8FAFC" : "#0F172A",
        bodyColor: isDark ? "#CBD5E1" : "#334155",
        borderColor: isDark ? "#1F2937" : "#CBD5E1",
        borderWidth: 1,
        callbacks: {
          afterBody: (items) => {
            const idx = items[0]?.dataIndex;
            if (idx !== undefined && sorted[idx]) {
              return `Avg Confidence: ${sorted[idx].avg_confidence}%`;
            }
            return "";
          },
        },
      },
    },
    scales: {
      x: {
        beginAtZero: true,
        ticks: { font: { size: 10 }, color: isDark ? "#94A3B8" : "#475569" },
        grid: { color: isDark ? "#1E293B" : "#E2E8F0" },
      },
      y: {
        ticks: { font: { size: 11, weight: 500 }, color: isDark ? "#CBD5E1" : "#1E293B" },
        grid: { display: false },
      },
    },
    maintainAspectRatio: false,
  };

  return (
    <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 md:p-5 shadow-sm h-full flex flex-col hover:border-slate-700 transition-all duration-200">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-bold text-slate-100">Predicted Threat Distribution</h3>
        <span className="text-xs font-normal text-slate-400">By Threat Category</span>
      </div>
      <div className="flex-1 min-h-[240px] md:min-h-[260px]">
        {sorted.length === 0 ? (
          <div className="h-full flex items-center justify-center text-xs text-slate-500">
            No threat summary data available
          </div>
        ) : (
          <Bar data={data} options={options} />
        )}
      </div>
    </div>
  );
}
