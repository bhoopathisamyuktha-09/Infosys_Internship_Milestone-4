import { Line } from "react-chartjs-2";
import {
  Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend, Filler,
} from "chart.js";
import { useTheme } from "../context/ThemeContext";

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend, Filler);

export default function EventTrendChart({ events }) {
  const { isDark } = useTheme();
  const sortedEvents = [...events]
    .filter((e) => e.timestamp)
    .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

  const buckets = {};
  sortedEvents.forEach((e) => {
    const hourLabel = new Date(e.timestamp).toLocaleString("en-US", {
      month: "short", day: "2-digit", hour: "2-digit",
    });
    buckets[hourLabel] = (buckets[hourLabel] || 0) + 1;
  });
  const labels = Object.keys(buckets);
  const counts = labels.map((l) => buckets[l]);

  const data = {
    labels,
    datasets: [{
      label: "Threat Events",
      data: counts,
      borderColor: "#3B82F6",
      backgroundColor: "rgba(59, 130, 246, 0.12)",
      fill: true,
      tension: 0.35,
      pointRadius: 3,
      pointHoverRadius: 5,
      pointBackgroundColor: "#3B82F6",
    }],
  };

  const options = {
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: isDark ? "#0B1329" : "#FFFFFF",
        titleColor: isDark ? "#F8FAFC" : "#0F172A",
        bodyColor: isDark ? "#CBD5E1" : "#334155",
        borderColor: isDark ? "#1F2937" : "#CBD5E1",
        borderWidth: 1,
      },
    },
    scales: {
      x: {
        ticks: { font: { size: 10 }, color: isDark ? "#94A3B8" : "#475569", maxRotation: 0, autoSkip: true },
        grid: { color: isDark ? "#1E293B" : "#E2E8F0" },
      },
      y: {
        beginAtZero: true,
        ticks: { font: { size: 10 }, color: isDark ? "#94A3B8" : "#475569" },
        grid: { color: isDark ? "#1E293B" : "#E2E8F0" },
      },
    },
    maintainAspectRatio: false,
  };

  return (
    <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 md:p-5 shadow-sm h-full flex flex-col hover:border-slate-700 hover:-translate-y-0.5 transition-all duration-200">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-bold text-slate-100">Telemetry Event Volume Over Time</h3>
        <span className="text-xs font-mono font-medium text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded border border-blue-500/20">
          Historical Telemetry
        </span>
      </div>
      <div className="flex-1 min-h-[280px]">
        <Line data={data} options={options} />
      </div>
    </div>
  );
}
