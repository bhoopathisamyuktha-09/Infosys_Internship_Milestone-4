import React, { useState, useEffect, useRef } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  FiShield,
  FiAlertTriangle,
  FiRefreshCw,
  FiArrowRight,
} from "react-icons/fi";
import { Line, Pie, Bar, Doughnut } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  PointElement,
  LineElement,
  ArcElement,
  Tooltip,
  Legend,
  Filler,
} from "chart.js";

import KpiCard from "../../components/KpiCard";
import ErrorBanner from "../../components/ErrorBanner";
import { RiskScoreBadge, RiskLevelBadge, PriorityBadge, StatusBadge } from "../../components/m3/RiskBadge";
import { useTheme } from "../../context/ThemeContext";
import {
  getDashboardOverview,
  getSecurityPosture,
  TIME_RANGE_OPTIONS,
} from "../../services/api";

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  PointElement,
  LineElement,
  ArcElement,
  Tooltip,
  Legend,
  Filler
);

const SEVERITY_COLORS = {
  Critical: "#EF4444",
  High: "#F97316",
  Medium: "#FBBF24",
  Low: "#10B981",
};

const STATUS_COLORS = {
  Open: "#EF4444",
  Investigating: "#3B82F6",
  Resolved: "#10B981",
  "False Positive": "#94A3B8",
};

export default function Overview() {
  const navigate = useNavigate();
  const { isDark } = useTheme();

  // State
  const [timeRange, setTimeRange] = useState("all");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);
  const [overview, setOverview] = useState(null);
  const [posture, setPosture] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(new Date());

  const isFirstLoad = useRef(true);

  async function loadData(isBackground = false) {
    if (!isBackground && isFirstLoad.current) {
      setLoading(true);
    } else {
      setRefreshing(true);
    }
    setError(null);
    try {
      const [ovData, postData] = await Promise.all([
        getDashboardOverview({ time_range: timeRange }),
        getSecurityPosture().catch(() => null),
      ]);
      setOverview(ovData);
      if (postData) setPosture(postData);
      setLastUpdated(new Date());
    } catch (err) {
      if (!overview) {
        setError(err.message || "Failed to load dashboard overview data");
      }
    } finally {
      setLoading(false);
      setRefreshing(false);
      isFirstLoad.current = false;
    }
  }

  useEffect(() => {
    loadData(false);
  }, [timeRange]);

  // 30-second silent background polling
  useEffect(() => {
    const timer = setInterval(() => {
      loadData(true);
    }, 30000);
    return () => clearInterval(timer);
  }, [timeRange]);

  if (loading && !overview) {
    return (
      <div className="flex items-center justify-center min-h-[450px]">
        <div className="flex items-center gap-3 text-slate-400 text-sm">
          <span className="h-2 w-2 rounded-full bg-blue-500 animate-ping"></span>
          <span>Aggregating real-time SOC security telemetry...</span>
        </div>
      </div>
    );
  }

  if (error && !overview) {
    return <ErrorBanner message={error} onRetry={() => loadData(false)} />;
  }

  // Risk Trend Timeline Chart
  const trend = overview?.risk_trend || [];
  const trendLabels = trend.map((t) => t.date);
  const trendIncidents = trend.map((t) => t.count);
  const trendAvgRisk = trend.map((t) => t.avg_risk_score);

  const trendData = {
    labels: trendLabels,
    datasets: [
      {
        label: "Incidents Prioritized",
        data: trendIncidents,
        borderColor: "#A855F7",
        backgroundColor: "rgba(168, 85, 247, 0.12)",
        fill: true,
        tension: 0.35,
        yAxisID: "y",
      },
      {
        label: "Avg Risk Score",
        data: trendAvgRisk,
        borderColor: "#3B82F6",
        backgroundColor: "rgba(59, 130, 246, 0.12)",
        fill: true,
        tension: 0.35,
        yAxisID: "y1",
      },
    ],
  };

  const trendOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: "top",
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
    scales: {
      x: {
        ticks: { font: { size: 10 }, color: isDark ? "#94A3B8" : "#475569" },
        grid: { color: isDark ? "#1E293B" : "#E2E8F0" },
      },
      y: {
        type: "linear",
        display: true,
        position: "left",
        beginAtZero: true,
        ticks: { font: { size: 10 }, color: isDark ? "#A855F7" : "#7E22CE" },
        grid: { color: isDark ? "#1E293B" : "#E2E8F0" },
      },
      y1: {
        type: "linear",
        display: true,
        position: "right",
        beginAtZero: true,
        max: 100,
        grid: { drawOnChartArea: false },
        ticks: { font: { size: 10 }, color: isDark ? "#3B82F6" : "#2563EB" },
      },
    },
  };

  // Severity Distribution Pie Chart
  const sevDist = overview?.threat_severity_distribution || {};
  const sevData = {
    labels: Object.keys(sevDist),
    datasets: [
      {
        data: Object.values(sevDist),
        backgroundColor: Object.keys(sevDist).map((k) => SEVERITY_COLORS[k] || "#64748B"),
        borderWidth: 0,
      },
    ],
  };

  // Threat Type Distribution Bar Chart
  const threatTypeDist = (overview?.threat_type_distribution || []).slice(0, 6);
  const threatTypeData = {
    labels: threatTypeDist.map((t) => t.threat_type),
    datasets: [
      {
        label: "Incidents",
        data: threatTypeDist.map((t) => t.count),
        backgroundColor: "#3B82F6",
        borderRadius: 6,
        maxBarThickness: 24,
      },
    ],
  };

  const threatTypeOptions = {
    indexAxis: "y",
    responsive: true,
    maintainAspectRatio: false,
    onClick: (evt, elements) => {
      if (elements && elements.length > 0) {
        const idx = elements[0].index;
        const selectedThreat = threatTypeDist[idx]?.threat_type;
        if (selectedThreat) {
          navigate(`/dashboard/incidents?threat_type=${encodeURIComponent(selectedThreat)}`);
        }
      }
    },
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
        beginAtZero: true,
        ticks: { font: { size: 10 }, color: isDark ? "#94A3B8" : "#475569" },
        grid: { color: isDark ? "#1E293B" : "#E2E8F0" },
      },
      y: {
        ticks: { font: { size: 11, weight: 500 }, color: isDark ? "#CBD5E1" : "#1E293B" },
        grid: { display: false },
      },
    },
  };

  // Incident Status Distribution Doughnut Chart
  const statusDist = overview?.incident_status_distribution || {};
  const statusData = {
    labels: Object.keys(statusDist),
    datasets: [
      {
        data: Object.values(statusDist),
        backgroundColor: Object.keys(statusDist).map((k) => STATUS_COLORS[k] || "#64748B"),
        borderWidth: 0,
      },
    ],
  };

  const recentIncidents = overview?.top_critical_incidents || [];

  return (
    <div className="grid gap-5 md:gap-6">
      {/* Top SOC Operations Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 bg-[#111827] border border-[#1F2937] rounded-xl p-4 md:p-5">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg md:text-xl font-extrabold text-slate-100">SOC Operations Overview</h2>
            <span className="px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30 text-[10px] font-bold font-mono">
              LIVE SOC MONITORING
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time threat telemetry, prioritized risk posture, and active incident response &bull; <span className="font-medium text-slate-300">Telemetry archive: Aug 1–7, 2025</span>
          </p>
        </div>

        {/* Action Controls: Time Range Toggle + Polling State + Refresh */}
        <div className="flex items-center gap-2.5 flex-wrap">
          {/* Time Range Filter Buttons */}
          <div className="flex items-center gap-2">
            <span className="hidden xl:inline-block text-[10px] font-mono text-slate-400 bg-[#1E293B] border border-[#1F2937] px-2 py-1 rounded-lg">
              Archive: Aug 1–7, 2025
            </span>
            <div className="flex items-center bg-[#1E293B] border border-[#1F2937] rounded-lg p-0.5">
              {TIME_RANGE_OPTIONS.map((opt) => (
                <button
                  key={opt.value}
                  onClick={() => setTimeRange(opt.value)}
                  className={`px-2.5 py-1 rounded-md text-xs font-semibold transition-all cursor-pointer ${
                    timeRange === opt.value
                      ? "bg-blue-600 text-white shadow-sm"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>

          {/* Polling Indicator */}
          <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-[#1E293B] border border-[#1F2937] text-[11px] text-slate-400">
            <span className={`w-2 h-2 rounded-full ${refreshing ? "bg-amber-400 animate-ping" : "bg-emerald-400 animate-pulse"}`}></span>
            <span>{refreshing ? "Refreshing..." : `Auto-Refresh 30s (${lastUpdated.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })})`}</span>
          </div>

          {/* Manual Refresh Button */}
          <button
            onClick={() => loadData(false)}
            disabled={refreshing || loading}
            title="Refresh dashboard metrics"
            className="flex items-center gap-1 px-3 py-1.5 rounded-lg border border-[#1F2937] bg-[#1E293B] hover:bg-slate-700 text-xs font-semibold text-slate-300 transition-colors cursor-pointer disabled:opacity-50"
          >
            <FiRefreshCw className={`text-xs ${refreshing || loading ? "animate-spin" : ""}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* 7 Dynamic KPI Cards */}
      <section className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-7 gap-3 md:gap-4">
        <KpiCard
          title="Total Events"
          value={(overview?.total_security_events ?? 0).toLocaleString()}
          statusText="Telemetry Stream"
          statusType="normal"
          iconType="activity"
        />
        <KpiCard
          title="Detected Threats"
          value={(overview?.detected_threats ?? 0).toLocaleString()}
          statusText="AI / Rules Flagged"
          statusType="moderate"
          iconType="lightning"
        />
        <KpiCard
          title="Critical Threats"
          value={(overview?.critical_threats ?? 0).toLocaleString()}
          statusText="Severity Level 4"
          statusType="critical"
          iconType="critical"
        />
        <KpiCard
          title="High Risk Incidents"
          value={(overview?.high_risk_incidents ?? 0).toLocaleString()}
          statusText="Score ≥ 61"
          statusType="critical"
          iconType="alert"
        />
        <KpiCard
          title="Active Incidents"
          value={(overview?.active_incidents ?? 0).toLocaleString()}
          statusText="Triage Required"
          statusType="moderate"
          iconType="alert"
        />
        <KpiCard
          title="Affected Assets"
          value={(overview?.affected_assets ?? 0).toLocaleString()}
          statusText="Network Hosts"
          statusType="normal"
          iconType="lock"
        />
        {/* Security Posture Widget Card — Stronger Visual Emphasis */}
        <Link
          to="/dashboard/executive"
          title="Highest-level organizational metric calculated by deterministic posture engine"
          className="bg-gradient-to-br from-[#1E1B4B]/40 via-[#111827] to-[#111827] border-2 border-purple-500/60 hover:border-purple-400 rounded-xl p-4 shadow-lg shadow-purple-950/30 flex flex-col justify-between transition-all duration-200 hover:-translate-y-0.5 group ring-1 ring-purple-500/30"
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-extrabold uppercase tracking-wider text-purple-300">Security Posture</span>
            <FiShield className="text-purple-400 text-base group-hover:scale-110 transition-transform" />
          </div>
          <div className="my-1 flex items-baseline gap-1.5">
            <span className="text-2xl lg:text-3xl font-extrabold font-mono text-purple-300 tracking-tight">
              {posture?.posture_score ?? overview?.security_posture?.posture_score ?? "--"}
            </span>
            <span className="text-xs text-slate-400">/ 100</span>
          </div>
          <div className="flex items-center justify-between text-[10px]">
            <span className="px-1.5 py-0.5 rounded font-bold bg-purple-500/25 text-purple-200 border border-purple-500/40">
              {posture?.posture_label || overview?.security_posture?.posture_label || "Evaluated"}
            </span>
            <span className="text-purple-300 font-semibold group-hover:underline flex items-center gap-0.5">
              <span>CISO View</span>
              <FiArrowRight className="text-[10px]" />
            </span>
          </div>
        </Link>
      </section>

      {/* Row 1 Charts: Risk Trend Over Time + Threat Severity Distribution */}
      <div className="grid gap-5 lg:grid-cols-3">
        {/* Risk Trend Timeline Chart (2 Cols) */}
        <div className="lg:col-span-2 bg-[#111827] border border-[#1F2937] rounded-xl p-4 md:p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-3">
            <div>
              <h3 className="text-sm font-bold text-slate-100">Telemetry Volume & Incident Progression Over Time</h3>
              <p className="text-xs text-slate-400">Correlated security events vs high-priority incidents</p>
            </div>
            <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-[#1E293B] text-slate-300 border border-[#1F2937]">
              Window: {timeRange.toUpperCase()}
            </span>
          </div>
          <div className="h-[280px]">
            <Line data={trendData} options={trendOptions} />
          </div>
        </div>

        {/* Threat Severity Distribution Pie Chart (1 Col) */}
        <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 md:p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-bold text-slate-100">Threat Severity Distribution</h3>
            <span className="text-xs text-slate-400">By Severity</span>
          </div>
          <div className="h-[280px]">
            <Pie
              data={sevData}
              options={{
                maintainAspectRatio: false,
                plugins: {
                  legend: {
                    position: "bottom",
                    labels: { boxWidth: 12, color: isDark ? "#94A3B8" : "#475569", font: { size: 11, weight: 600 } },
                  },
                },
              }}
            />
          </div>
        </div>
      </div>

      {/* Row 2 Charts: Threat Type Distribution + Incident Status Distribution */}
      <div className="grid gap-5 lg:grid-cols-2">
        {/* Threat Type Distribution with Clickable Drill-down */}
        <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 md:p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-3">
            <div>
              <h3 className="text-sm font-bold text-slate-100">Top Threat Categories</h3>
              <p className="text-xs text-slate-400">Click any threat bar to drill down to filtered incidents</p>
            </div>
            <span className="text-xs font-mono text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded border border-blue-500/20">
              Interactive Drill-Down
            </span>
          </div>
          <div className="h-[260px]">
            <Bar data={threatTypeData} options={threatTypeOptions} />
          </div>
        </div>

        {/* Incident Status Distribution Doughnut Chart */}
        <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 md:p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-3">
            <div>
              <h3 className="text-sm font-bold text-slate-100">Incident Triage Lifecycle Distribution</h3>
              <p className="text-xs text-slate-400">Resolution pipeline: Open, Investigating, Resolved, False Positive</p>
            </div>
            <Link
              to="/dashboard/incidents"
              className="text-xs text-blue-400 hover:text-blue-300 font-semibold flex items-center gap-1"
            >
              <span>Queue</span>
              <FiArrowRight />
            </Link>
          </div>
          <div className="h-[260px]">
            <Doughnut
              data={statusData}
              options={{
                maintainAspectRatio: false,
                plugins: {
                  legend: {
                    position: "bottom",
                    labels: { boxWidth: 12, color: isDark ? "#94A3B8" : "#475569", font: { size: 11, weight: 600 } },
                  },
                },
              }}
            />
          </div>
        </div>
      </div>

      {/* Critical Incidents Panel (Every Incident Clickable to IncidentDetails) */}
      <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 md:p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-[#1F2937] pb-3">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-red-500/15 text-red-400 border border-red-500/30">
              <FiAlertTriangle className="text-base" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-100">Immediate Critical Incidents Queue</h3>
              <p className="text-xs text-slate-400">High & Critical priority incidents requiring immediate analyst triage</p>
            </div>
          </div>

          <Link
            to="/dashboard/incidents"
            className="text-xs text-blue-400 hover:text-blue-300 font-semibold flex items-center gap-1"
          >
            <span>View All Incidents</span>
            <FiArrowRight />
          </Link>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-[#1F2937] text-[10px] font-bold text-slate-400 uppercase bg-[#0B1329]">
                <th className="py-2.5 px-3">Incident ID</th>
                <th className="py-2.5 px-3">Threat</th>
                <th className="py-2.5 px-3">Asset</th>
                <th className="py-2.5 px-3">Risk Score</th>
                <th className="py-2.5 px-3">Priority</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1F2937]">
              {recentIncidents.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-6 text-slate-400 text-xs">
                    No critical incidents pending triage in current time window.
                  </td>
                </tr>
              ) : (
                recentIncidents.map((inc) => (
                  <tr
                    key={inc.incident_id}
                    onClick={() => navigate(`/dashboard/incidents/${inc.incident_id}`)}
                    className="hover:bg-[#1E293B]/60 transition-colors cursor-pointer group"
                  >
                    <td className="py-2.5 px-3 font-mono font-bold text-blue-400 group-hover:underline">
                      {inc.incident_id}
                    </td>
                    <td className="py-2.5 px-3 text-slate-200 font-semibold">
                      {inc.threat_type}
                    </td>
                    <td className="py-2.5 px-3 text-slate-300">
                      {inc.asset_name || "Enterprise Host"}
                    </td>
                    <td className="py-2.5 px-3">
                      <div className="flex items-center gap-1.5">
                        <RiskScoreBadge score={inc.risk_score} level={inc.risk_level} size="sm" />
                        <RiskLevelBadge level={inc.risk_level} size="sm" />
                      </div>
                    </td>
                    <td className="py-2.5 px-3">
                      <PriorityBadge priority={inc.priority} size="sm" />
                    </td>
                    <td className="py-2.5 px-3">
                      <StatusBadge status={inc.status} size="sm" />
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-blue-600 hover:bg-blue-700 text-white font-semibold text-[11px] shadow-xs transition-colors">
                        <span>Investigate</span>
                        <FiArrowRight />
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
