import React, { useState } from "react";
import { Link } from "react-router-dom";
import {
  FiShield,
  FiAlertTriangle,
  FiArrowRight,
  FiTrendingUp,
  FiLayers,
  FiSliders,
} from "react-icons/fi";
import { Doughnut, Line } from "react-chartjs-2";
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Filler,
} from "chart.js";

import KpiCard from "../../components/KpiCard";
import ErrorBanner from "../../components/ErrorBanner";
import { RiskLevelBadge, PriorityBadge, StatusBadge, RiskScoreBadge } from "../../components/m3/RiskBadge";
import RiskWeightConfigModal from "../../components/m3/RiskWeightConfigModal";
import { getRiskSummary, getHighRiskIncidents } from "../../services/api";
import { useAsyncData } from "../../hooks/useAsyncData";

ChartJS.register(
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Filler
);

export default function RiskOverview() {
  const [isWeightModalOpen, setIsWeightModalOpen] = useState(false);

  const { data, loading, error, reload } = useAsyncData(async () => {
    const [summary, highRisk] = await Promise.all([
      getRiskSummary(),
      getHighRiskIncidents({ limit: 5, min_score: 61 }),
    ]);
    return { summary, highRisk: highRisk.items || [] };
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="flex items-center gap-3 text-slate-400 text-sm">
          <span className="h-2 w-2 rounded-full bg-blue-500 animate-ping"></span>
          <span>Loading M3 Security Risk Intelligence...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return <ErrorBanner message={error} onRetry={reload} />;
  }

  const { summary, highRisk } = data;
  const dist = summary?.risk_distribution || {};

  // Doughnut Chart Configuration
  const doughnutData = {
    labels: ["Critical (81-100)", "High (61-80)", "Moderate (41-60)", "Medium (21-40)", "Low (0-20)"],
    datasets: [
      {
        data: [
          dist.Critical || 0,
          dist.High || 0,
          dist.Moderate || 0,
          dist.Medium || 0,
          dist.Low || 0,
        ],
        backgroundColor: ["#EF4444", "#F97316", "#F59E0B", "#3B82F6", "#10B981"],
        borderColor: "#111827",
        borderWidth: 2,
      },
    ],
  };

  const doughnutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: "bottom",
        labels: {
          color: "#94A3B8",
          font: { size: 11, family: "inherit" },
          padding: 12,
          usePointStyle: true,
        },
      },
      tooltip: {
        backgroundColor: "#1E293B",
        titleColor: "#F8FAFC",
        bodyColor: "#E2E8F0",
        borderColor: "#334155",
        borderWidth: 1,
      },
    },
    cutout: "68%",
  };

  // Trend Chart Configuration
  const trendLabels = summary.trend?.map((t) => t.date) || [];
  const trendCounts = summary.trend?.map((t) => t.count) || [];
  const trendRiskAvg = summary.trend?.map((t) => t.avg_risk_score) || [];

  const lineData = {
    labels: trendLabels.length ? trendLabels : ["No Trend Data"],
    datasets: [
      {
        label: "Daily Incidents",
        data: trendCounts.length ? trendCounts : [0],
        borderColor: "#3B82F6",
        backgroundColor: "rgba(59, 130, 246, 0.15)",
        fill: true,
        tension: 0.3,
        yAxisID: "y",
      },
      {
        label: "Avg Risk Score",
        data: trendRiskAvg.length ? trendRiskAvg : [0],
        borderColor: "#EF4444",
        backgroundColor: "transparent",
        borderDash: [4, 4],
        tension: 0.3,
        yAxisID: "y1",
      },
    ],
  };

  const lineOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: "top",
        labels: { color: "#94A3B8", font: { size: 11 }, usePointStyle: true },
      },
      tooltip: {
        backgroundColor: "#1E293B",
        titleColor: "#F8FAFC",
        bodyColor: "#E2E8F0",
        borderColor: "#334155",
        borderWidth: 1,
      },
    },
    scales: {
      x: {
        grid: { color: "rgba(51, 65, 85, 0.2)" },
        ticks: { color: "#64748B", font: { size: 10 } },
      },
      y: {
        type: "linear",
        position: "left",
        grid: { color: "rgba(51, 65, 85, 0.2)" },
        ticks: { color: "#64748B", font: { size: 10 } },
      },
      y1: {
        type: "linear",
        position: "right",
        min: 0,
        max: 100,
        grid: { drawOnChartArea: false },
        ticks: { color: "#EF4444", font: { size: 10 } },
      },
    },
  };

  return (
    <div className="grid gap-5 md:gap-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#111827] border border-[#1F2937] rounded-xl p-4 md:p-5">
        <div>
          <div className="flex items-center gap-2">
            <FiShield className="text-blue-400 text-xl" />
            <h2 className="text-lg md:text-xl font-bold text-slate-100">Risk Overview & Prioritization</h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real-time multi-factor deterministic security posture & prioritized incident telemetry
          </p>
        </div>

        <div className="flex items-center gap-2.5 flex-wrap">
          <button
            type="button"
            onClick={() => setIsWeightModalOpen(true)}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-[#1E293B] hover:bg-slate-700 text-slate-200 border border-[#334155] text-xs font-semibold shadow-xs transition-colors cursor-pointer"
          >
            <FiSliders className="text-blue-400 text-sm" />
            <span>Configure Risk Weights</span>
          </button>

          <Link
            to="/dashboard/incidents"
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-md transition-colors"
          >
            <span>View All Priority Incidents</span>
            <FiArrowRight />
          </Link>
        </div>
      </div>

      {/* Mentor Required KPI Summary Cards */}
      <section className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 xl:grid-cols-8 gap-3 md:gap-3.5">
        <KpiCard
          title="Total Incidents"
          value={summary.total_incidents.toLocaleString()}
          statusText="M3 Correlated"
          statusType="normal"
          iconType="activity"
        />
        <KpiCard
          title="Critical (81-100)"
          value={summary.critical_count.toLocaleString()}
          statusText="Immediate Action"
          statusType="critical"
          iconType="critical"
        />
        <KpiCard
          title="High (61-80)"
          value={summary.high_count.toLocaleString()}
          statusText="High Priority"
          statusType="moderate"
          iconType="lightning"
        />
        <KpiCard
          title="Moderate (41-60)"
          value={summary.moderate_count.toLocaleString()}
          statusText="Elevated Review"
          statusType="normal"
          iconType="lock"
        />
        <KpiCard
          title="Medium (21-40)"
          value={(summary.medium_count || 0).toLocaleString()}
          statusText="Standard Monitoring"
          statusType="normal"
          iconType="activity"
        />
        <KpiCard
          title="Low (0-20)"
          value={(summary.low_count || 0).toLocaleString()}
          statusText="Routine Telemetry"
          statusType="normal"
          iconType="lock"
        />
        <KpiCard
          title="Open Incidents"
          value={summary.open_count.toLocaleString()}
          statusText="Active Queue"
          statusType="critical"
          iconType="alert"
        />
        <KpiCard
          title="Investigating"
          value={summary.investigating_count.toLocaleString()}
          statusText="Under Review"
          statusType="moderate"
          iconType="activity"
        />
      </section>

      {/* Visual Risk Distribution & Trend Charts */}
      <div className="grid gap-5 lg:grid-cols-12">
        {/* Risk Distribution Doughnut Card */}
        <div className="lg:col-span-4 bg-[#111827] border border-[#1F2937] rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-[#1F2937] pb-3 mb-4">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <FiLayers className="text-blue-400" />
                <span>Risk Level Distribution</span>
              </h3>
              <span className="text-[11px] font-mono text-slate-400">Total: {summary.total_incidents}</span>
            </div>
            <div className="h-56 relative flex items-center justify-center">
              <Doughnut data={doughnutData} options={doughnutOptions} />
            </div>
          </div>

          <div className="grid grid-cols-5 gap-1 pt-4 border-t border-[#1F2937] text-center text-[10px]">
            <div>
              <div className="text-red-400 font-bold font-mono">{dist.Critical || 0}</div>
              <div className="text-slate-400 truncate">Critical</div>
            </div>
            <div>
              <div className="text-orange-400 font-bold font-mono">{dist.High || 0}</div>
              <div className="text-slate-400 truncate">High</div>
            </div>
            <div>
              <div className="text-amber-400 font-bold font-mono">{dist.Moderate || 0}</div>
              <div className="text-slate-400 truncate">Moderate</div>
            </div>
            <div>
              <div className="text-blue-400 font-bold font-mono">{dist.Medium || 0}</div>
              <div className="text-slate-400 truncate">Medium</div>
            </div>
            <div>
              <div className="text-emerald-400 font-bold font-mono">{dist.Low || 0}</div>
              <div className="text-slate-400 truncate">Low</div>
            </div>
          </div>
        </div>

        {/* Risk Trend & Volume Line Card */}
        <div className="lg:col-span-8 bg-[#111827] border border-[#1F2937] rounded-xl p-5">
          <div className="flex items-center justify-between border-b border-[#1F2937] pb-3 mb-4">
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <FiTrendingUp className="text-emerald-400" />
              <span>Incident Velocity & Risk Trend</span>
            </h3>
            <span className="text-[11px] text-slate-400">Daily Timeline Progression</span>
          </div>
          <div className="h-64">
            <Line data={lineData} options={lineOptions} />
          </div>
        </div>
      </div>

      {/* Top High-Risk Incidents Spotlight Table */}
      <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-[#1F2937] pb-3">
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <FiAlertTriangle className="text-red-400" />
              <span>Top Critical & High Risk Incidents</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Prioritized by Enterprise Risk Score (score ≥ 61)
            </p>
          </div>

          <Link
            to="/dashboard/incidents"
            className="text-xs text-blue-400 hover:text-blue-300 font-semibold flex items-center gap-1"
          >
            <span>View All ({summary.total_incidents})</span>
            <FiArrowRight />
          </Link>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-[#1F2937] text-slate-400 font-semibold">
                <th className="py-2.5 px-3">Score</th>
                <th className="py-2.5 px-3">Incident ID</th>
                <th className="py-2.5 px-3">Threat Type</th>
                <th className="py-2.5 px-3">Risk Level</th>
                <th className="py-2.5 px-3">Priority</th>
                <th className="py-2.5 px-3">Asset</th>
                <th className="py-2.5 px-3">User</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1F2937]">
              {highRisk.map((inc) => (
                <tr key={inc.incident_id} className="hover:bg-[#1E293B]/60 transition-colors">
                  <td className="py-2.5 px-3">
                    <RiskScoreBadge score={inc.risk_score} level={inc.risk_level} size="sm" />
                  </td>
                  <td className="py-2.5 px-3 font-mono font-bold text-blue-400">
                    <Link to={`/dashboard/incidents/${inc.incident_id}`} className="hover:underline">
                      {inc.incident_id}
                    </Link>
                  </td>
                  <td className="py-2.5 px-3 font-semibold text-slate-200">{inc.threat_type}</td>
                  <td className="py-2.5 px-3">
                    <RiskLevelBadge level={inc.risk_level} />
                  </td>
                  <td className="py-2.5 px-3">
                    <PriorityBadge priority={inc.priority} />
                  </td>
                  <td className="py-2.5 px-3 text-slate-300 font-medium">{inc.asset_name || "Unknown"}</td>
                  <td className="py-2.5 px-3 font-mono text-slate-300">{inc.affected_user || "system"}</td>
                  <td className="py-2.5 px-3">
                    <StatusBadge status={inc.status} />
                  </td>
                  <td className="py-2.5 px-3 text-right">
                    <Link
                      to={`/dashboard/incidents/${inc.incident_id}`}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-blue-600 hover:bg-blue-700 text-white font-semibold shadow-xs transition-colors text-xs"
                    >
                      <span>Investigate</span>
                      <FiArrowRight className="text-xs" />
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Risk Weight Configuration Modal */}
      <RiskWeightConfigModal
        isOpen={isWeightModalOpen}
        onClose={() => setIsWeightModalOpen(false)}
      />
    </div>
  );
}
