import { Pie } from "react-chartjs-2";
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from "chart.js";
import { useTheme } from "../context/ThemeContext";

ChartJS.register(ArcElement, Tooltip, Legend);

const COLORS = { Critical: "#EF4444", High: "#F97316", Medium: "#FBBF24", Low: "#10B981" };

export default function ThreatDistributionChart({ events }) {
  const { isDark } = useTheme();
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  events.forEach((e) => { counts[e.severity] = (counts[e.severity] || 0) + 1; });

  const data = {
    labels: Object.keys(counts),
    datasets: [{
      data: Object.values(counts),
      backgroundColor: Object.keys(counts).map((k) => COLORS[k]),
      borderWidth: 0,
    }],
  };

  const options = {
    plugins: {
      legend: {
        position: "bottom",
        labels: { boxWidth: 12, color: isDark ? "#94A3B8" : "#475569", font: { size: 11, weight: 600 } },
      },
      tooltip: {
        backgroundColor: isDark ? "#0B1329" : "#FFFFFF",
        titleColor: isDark ? "#F8FAFC" : "#0F172A",
        bodyColor: isDark ? "#CBD5E1" : "#334155",
        borderColor: isDark ? "#1F2937" : "#CBD5E1",
        borderWidth: 1,
      },
    },
    maintainAspectRatio: false,
  };

  return (
    <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 md:p-5 shadow-sm h-full flex flex-col hover:border-slate-700 hover:-translate-y-0.5 transition-all duration-200">
      <h3 className="text-sm font-bold text-slate-100 mb-3 flex items-center justify-between">
        <span>Threat Distribution</span>
        <span className="text-xs font-normal text-slate-400">By Severity</span>
      </h3>
      <div className="flex-1 min-h-[260px] md:min-h-[280px]">
        <Pie data={data} options={options} />
      </div>
    </div>
  );
}
