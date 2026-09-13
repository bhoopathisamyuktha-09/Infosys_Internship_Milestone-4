import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import {
  FiServer,
  FiCheckCircle,
  FiRefreshCw,
  FiArrowRight,
  FiPieChart,
  FiDownload,
  FiChevronDown,
  FiChevronUp,
  FiAlertCircle,
  FiShield,
} from "react-icons/fi";
import { Bar, Pie, Line } from "react-chartjs-2";
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

import ErrorBanner from "../../components/ErrorBanner";
import KpiCard from "../../components/KpiCard";
import { useTheme } from "../../context/ThemeContext";
import {
  getExecutiveSummary,
  getSecurityPosture,
  getDashboardOverview,
  getSecurityReportCsvUrl,
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

const TIER_COLORS = {
  Excellent: { text: "text-emerald-400", bg: "bg-emerald-500/20", border: "border-emerald-500/30", ring: "#10B981" },
  Good: { text: "text-blue-400", bg: "bg-blue-500/20", border: "border-blue-500/30", ring: "#3B82F6" },
  Moderate: { text: "text-amber-400", bg: "bg-amber-500/20", border: "border-amber-500/30", ring: "#F59E0B" },
  Poor: { text: "text-orange-400", bg: "bg-orange-500/20", border: "border-orange-500/30", ring: "#F97316" },
  Critical: { text: "text-red-400", bg: "bg-red-500/20", border: "border-red-500/30", ring: "#EF4444" },
};

export default function Executive() {
  const { isDark } = useTheme();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [executiveData, setExecutiveData] = useState(null);
  const [postureData, setPostureData] = useState(null);
  const [overviewData, setOverviewData] = useState(null);
  const [lastRefreshed, setLastRefreshed] = useState(new Date());
  const [showMathDetails, setShowMathDetails] = useState(false);

  async function loadData() {
    setLoading(true);
    setError(null);
    try {
      const [exec, posture, overview] = await Promise.all([
        getExecutiveSummary(),
        getSecurityPosture(),
        getDashboardOverview({ time_range: "all" }),
      ]);
      setExecutiveData(exec);
      setPostureData(posture);
      setOverviewData(overview);
      setLastRefreshed(new Date());
    } catch (err) {
      setError(err.message || "Failed to load executive security intelligence");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
    // 60-second background polling
    const interval = setInterval(() => {
      loadData();
    }, 60000);
    return () => clearInterval(interval);
  }, []);

  if (loading && !executiveData) {
    return (
      <div className="flex items-center justify-center min-h-[450px]">
        <div className="flex items-center gap-3 text-slate-400 text-sm">
          <span className="h-2 w-2 rounded-full bg-purple-500 animate-ping"></span>
          <span>Synthesizing executive security overview...</span>
        </div>
      </div>
    );
  }

  if (error && !executiveData) {
    return <ErrorBanner message={error} onRetry={loadData} />;
  }

  const posture = postureData || executiveData?.security_posture || {};
  const tierStyle = TIER_COLORS[posture.posture_label] || TIER_COLORS.Moderate;
  const factors = posture.contributing_factors || {};

  // Timeline Trend Data for Chart
  const trend = executiveData?.threat_trend || overviewData?.risk_trend || [];
  const trendLabels = trend.map((t) => t.date);
  const trendIncidents = trend.map((t) => t.count);
  const trendAvgRisk = trend.map((t) => t.avg_risk_score);

  const trendChartData = {
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

  const trendChartOptions = {
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

  // Threat Breakdown Data for Horizontal Bar Chart
  const topThreats = (executiveData?.top_threat_categories || overviewData?.threat_type_distribution || []).slice(0, 5);
  const threatChartData = {
    labels: topThreats.map((t) => t.threat_type || t.category || "Threat"),
    datasets: [
      {
        label: "Incidents",
        data: topThreats.map((t) => t.count),
        backgroundColor: "#6366F1",
        borderRadius: 6,
        maxBarThickness: 24,
      },
    ],
  };

  const threatChartOptions = {
    indexAxis: "y",
    responsive: true,
    maintainAspectRatio: false,
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

  // Severity Distribution Pie Chart
  const sevDist = overviewData?.threat_severity_distribution || {};
  const sevColors = { Critical: "#EF4444", High: "#F97316", Medium: "#FBBF24", Low: "#10B981" };
  const sevChartData = {
    labels: Object.keys(sevDist),
    datasets: [
      {
        data: Object.values(sevDist),
        backgroundColor: Object.keys(sevDist).map((k) => sevColors[k] || "#64748B"),
        borderWidth: 0,
      },
    ],
  };

  // Plain-English headline based on score tier
  const postureHeadline =
    posture.posture_score < 30
      ? "Security posture requires immediate executive attention."
      : posture.posture_score < 60
      ? "Security posture is degraded; high-priority remediation is required."
      : "Security posture is stable within operational defensive parameters.";

  return (
    <div className="grid gap-5 md:gap-6">
      {/* Executive Header */}
      <div className={`flex flex-col sm:flex-row sm:items-center justify-between gap-3 rounded-xl p-4 md:p-5 border ${
        isDark ? "bg-[#111827] border-[#1F2937]" : "bg-white border-slate-200 shadow-xs"
      }`}>
        <div>
          <div className="flex items-center gap-2">
            <FiPieChart className={`text-xl ${isDark ? "text-purple-400" : "text-purple-600"}`} />
            <h2 className={`text-lg md:text-xl font-bold ${isDark ? "text-slate-100" : "text-slate-900"}`}>Executive Security Overview</h2>
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono border ${
              isDark ? "bg-purple-500/20 text-purple-300 border-purple-500/30" : "bg-purple-50 text-purple-700 border-purple-200"
            }`}>
              STRATEGIC CISO VIEW
            </span>
          </div>
          <p className={`text-xs mt-1 ${isDark ? "text-slate-400" : "text-slate-600"}`}>
            High-level posture analysis, operational health metrics, and executive threat trends
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <span className={`text-[11px] ${isDark ? "text-slate-400" : "text-slate-500"}`}>
            Updated {lastRefreshed.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
          </span>
          <button
            onClick={loadData}
            disabled={loading}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-semibold transition-colors cursor-pointer ${
              isDark
                ? "border-[#1F2937] bg-[#1E293B] hover:bg-slate-700 text-slate-300"
                : "border-slate-300 bg-slate-100 hover:bg-slate-200 text-slate-700"
            }`}
          >
            <FiRefreshCw className={loading ? "animate-spin" : ""} />
            <span>Refresh</span>
          </button>
          <a
            href={getSecurityReportCsvUrl()}
            download="sentinelai_security_report.csv"
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-xs font-semibold text-white shadow transition-colors"
          >
            <FiDownload />
            <span>Export Report (CSV)</span>
          </a>
        </div>
      </div>

      {/* Primary Security Posture Card (Redesigned for Executive Clarity) */}
      <div className={`rounded-xl p-5 md:p-6 space-y-5 border shadow-sm ${
        isDark
          ? "bg-gradient-to-br from-[#111827] via-[#151D31] to-[#1E1B4B]/30 border-purple-500/20"
          : "bg-gradient-to-br from-white via-slate-50 to-purple-50/40 border-purple-200/80 shadow-md"
      }`}>
        {/* Top Hero: Big Primary Message */}
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
          <div className="flex items-center gap-5">
            {/* Score Ring */}
            <div className={`relative flex items-center justify-center h-24 w-24 rounded-full border-4 shrink-0 shadow-inner ${
              isDark ? "border-[#1F2937] bg-[#0B1329]" : "border-slate-200 bg-white"
            }`}>
              <div className="text-center">
                <span className={`text-3xl font-extrabold font-mono tracking-tight ${
                  isDark ? tierStyle.text : (posture.posture_score < 40 ? "text-red-600" : "text-emerald-600")
                }`}>
                  {posture.posture_score ?? "--"}
                </span>
                <span className={`block text-[10px] uppercase font-bold tracking-wider ${isDark ? "text-slate-400" : "text-slate-500"}`}>
                  / 100
                </span>
              </div>
            </div>

            <div className="space-y-1">
              <div className="flex items-center gap-2.5">
                <span className={`text-xs uppercase tracking-wider font-bold ${isDark ? "text-slate-400" : "text-slate-500"}`}>
                  Organizational Security Posture
                </span>
                <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold border ${
                  isDark
                    ? `${tierStyle.bg} ${tierStyle.text} ${tierStyle.border}`
                    : (posture.posture_label === "Critical" ? "bg-red-50 text-red-700 border-red-200" : "bg-emerald-50 text-emerald-700 border-emerald-200")
                }`}>
                  {posture.posture_label || "Evaluated"}
                </span>
              </div>
              <h3 className={`text-base md:text-xl font-extrabold ${isDark ? "text-slate-100" : "text-slate-900"}`}>
                {postureHeadline}
              </h3>
              <p className={`text-xs ${isDark ? "text-slate-400" : "text-slate-600"}`}>
                Composite health rating synthesized from live telemetry, active high-priority incidents, and enterprise asset exposure.
              </p>
            </div>
          </div>

          <div className={`rounded-xl p-3.5 text-xs space-y-1.5 shrink-0 w-full lg:w-auto border ${
            isDark ? "bg-[#111827]/90 border-[#1F2937]" : "bg-white border-slate-200 shadow-xs"
          }`}>
            <div className={`flex justify-between gap-6 ${isDark ? "text-slate-400" : "text-slate-600"}`}>
              <span>Baseline Security:</span>
              <strong className={`font-mono ${isDark ? "text-slate-200" : "text-slate-800"}`}>100.0 pts</strong>
            </div>
            <div className={`flex justify-between gap-6 ${isDark ? "text-slate-400" : "text-slate-600"}`}>
              <span>Telemetry Deductions:</span>
              <strong className={`font-mono ${isDark ? "text-red-400" : "text-red-600"}`}>-{posture.total_deduction || 0} pts</strong>
            </div>
            <div className={`border-t pt-1 flex justify-between gap-6 font-semibold ${
              isDark ? "border-[#1F2937] text-slate-200" : "border-slate-200 text-slate-800"
            }`}>
              <span>Active Posture:</span>
              <span className={`font-mono font-bold ${isDark ? tierStyle.text : "text-red-600"}`}>
                {posture.posture_score ?? "--"} / 100 ({posture.posture_label})
              </span>
            </div>
          </div>
        </div>

        {/* Visual Explanation: Primary Risk Drivers */}
        <div className={`pt-3 border-t space-y-2.5 ${isDark ? "border-[#1F2937]" : "border-slate-200"}`}>
          <div className="flex items-center justify-between">
            <span className={`text-xs font-bold uppercase tracking-wider ${isDark ? "text-slate-300" : "text-slate-700"}`}>
              Key Risk Drivers & Deductions
            </span>
            <button
              onClick={() => setShowMathDetails(!showMathDetails)}
              className={`text-xs font-semibold inline-flex items-center gap-1 cursor-pointer transition-colors ${
                isDark ? "text-purple-400 hover:text-purple-300" : "text-purple-600 hover:text-purple-700"
              }`}
            >
              <span>{showMathDetails ? "Hide Calculation Formula" : "View Calculation Details"}</span>
              {showMathDetails ? <FiChevronUp /> : <FiChevronDown />}
            </button>
          </div>

          {/* 5 Risk Driver Visual Bars */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
            {Object.entries(factors).map(([key, f]) => (
              <div key={key} className={`rounded-lg p-3 space-y-1.5 border ${
                isDark ? "bg-[#1E293B]/70 border-[#1F2937]" : "bg-white border-slate-200 shadow-xs"
              }`}>
                <div className="flex justify-between items-center text-[11px]">
                  <span className={`capitalize truncate font-semibold ${isDark ? "text-slate-300" : "text-slate-800"}`}>
                    {key.replace(/_/g, " ")}
                  </span>
                  <span className={`font-mono text-xs font-bold ${isDark ? "text-red-400" : "text-red-600"}`}>
                    -{f.points_deducted ?? 0} pts
                  </span>
                </div>
                <div className={`h-1.5 w-full rounded-full overflow-hidden ${isDark ? "bg-[#111827]" : "bg-slate-200"}`}>
                  <div
                    className={`h-full rounded-full transition-all ${isDark ? "bg-red-500" : "bg-red-600"}`}
                    style={{ width: `${Math.min(100, Math.max(0, f.normalized_score ?? 0))}%` }}
                  />
                </div>
                <div className={`flex justify-between items-center text-[10px] ${isDark ? "text-slate-400" : "text-slate-500"}`}>
                  <span className="truncate" title={f.explanation}>{f.explanation}</span>
                  <span className={`font-mono shrink-0 ml-1 ${isDark ? "text-purple-300" : "text-purple-600 font-semibold"}`}>W: {((f.weight ?? 0.2) * 100).toFixed(0)}%</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Collapsible Detailed Mathematical Calculation */}
        {showMathDetails && (
          <div className={`mt-3 p-4 rounded-xl border text-xs space-y-3 anim-fade-card ${
            isDark
              ? "border-purple-500/30 bg-[#0B1329]/95 text-slate-300"
              : "border-purple-200 bg-purple-50/50 text-slate-800 shadow-xs"
          }`}>
            <div className={`flex items-center gap-2 border-b pb-2 ${isDark ? "border-[#1F2937]" : "border-purple-200"}`}>
              <FiShield className={`text-sm ${isDark ? "text-purple-400" : "text-purple-600"}`} />
              <h4 className={`font-bold ${isDark ? "text-slate-200" : "text-slate-900"}`}>
                Deterministic Posture Engine — Exact Calculation Breakdown
              </h4>
            </div>

            <div className={`grid grid-cols-1 md:grid-cols-2 gap-4 ${isDark ? "text-slate-300" : "text-slate-700"}`}>
              <div className="space-y-1.5">
                <p className={`text-[11px] font-mono ${isDark ? "text-slate-400" : "text-slate-500"}`}>
                  FORMULA: Posture = max(0, round(100.0 - ∑ [Weight × Normalized Deductions]))
                </p>
                <div className="space-y-1">
                  <div className="flex justify-between">
                    <span>Baseline Organizational Score:</span>
                    <span className={`font-mono font-bold ${isDark ? "text-slate-100" : "text-slate-900"}`}>100.0 pts</span>
                  </div>
                  <div className={`flex justify-between ${isDark ? "text-red-400" : "text-red-600"}`}>
                    <span>Active Incidents Penalty (25% weight):</span>
                    <span className="font-mono font-bold">-{factors.active_incidents?.points_deducted ?? 25.0} pts</span>
                  </div>
                  <div className={`flex justify-between ${isDark ? "text-red-400" : "text-red-600"}`}>
                    <span>Asset Exposure Penalty (20% weight):</span>
                    <span className="font-mono font-bold">-{factors.asset_exposure?.points_deducted ?? 20.0} pts</span>
                  </div>
                  <div className={`flex justify-between ${isDark ? "text-red-400" : "text-red-600"}`}>
                    <span>Unresolved Threats Penalty (20% weight):</span>
                    <span className="font-mono font-bold">-{factors.unresolved_threats?.points_deducted ?? 20.0} pts</span>
                  </div>
                  <div className={`flex justify-between ${isDark ? "text-red-400" : "text-red-600"}`}>
                    <span>Threat Volume Ratio Penalty (10% weight):</span>
                    <span className="font-mono font-bold">-{factors.threat_volume?.points_deducted ?? 5.1} pts</span>
                  </div>
                  <div className={`flex justify-between ${isDark ? "text-red-400" : "text-red-600"}`}>
                    <span>Critical Vulnerabilities Penalty (25% weight):</span>
                    <span className="font-mono font-bold">-{factors.critical_vulnerabilities?.points_deducted ?? 2.8} pts</span>
                  </div>
                </div>
              </div>

              <div className={`space-y-2 border-l pl-4 ${isDark ? "border-[#1F2937]" : "border-purple-200"}`}>
                <div className="flex justify-between font-semibold">
                  <span>Total Applied Telemetry Deductions:</span>
                  <span className={`font-mono font-bold ${isDark ? "text-red-400" : "text-red-600"}`}>-{posture.total_deduction ?? 72.9} pts</span>
                </div>
                <div className="flex justify-between font-semibold">
                  <span>Raw Calculated Score:</span>
                  <span className={`font-mono font-bold ${isDark ? "text-purple-300" : "text-purple-700"}`}>
                    {(100.0 - (posture.total_deduction || 0)).toFixed(1)} pts
                  </span>
                </div>
                <div className={`flex justify-between font-extrabold text-sm border-t pt-2 ${
                  isDark ? "border-[#1F2937] text-slate-100" : "border-purple-200 text-slate-900"
                }`}>
                  <span>Final Displayed Posture:</span>
                  <span className={`font-mono font-bold ${isDark ? tierStyle.text : "text-red-600"}`}>
                    {posture.posture_score ?? 29} / 100 ({posture.posture_label || "Critical"})
                  </span>
                </div>
                <p className={`text-[11px] italic pt-1 ${isDark ? "text-slate-400" : "text-slate-500"}`}>
                  {posture.calculation_explanation}
                </p>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Executive Key Takeaway Box (Part 9: 5-Second Managerial Read) */}
      <div className={`border-l-4 border-red-500 rounded-xl p-4 md:p-5 border ${
        isDark
          ? "bg-gradient-to-r from-red-500/10 via-purple-500/10 to-blue-500/10 border-[#1F2937]"
          : "bg-red-50/70 border-red-200 shadow-xs"
      }`}>
        <div className="flex items-center gap-2 mb-1.5">
          <FiAlertCircle className={`text-base shrink-0 ${isDark ? "text-red-400" : "text-red-600"}`} />
          <h4 className={`text-xs font-bold uppercase tracking-wider font-mono ${isDark ? "text-red-300" : "text-red-700"}`}>
            EXECUTIVE TAKEAWAY
          </h4>
        </div>
        <p className={`text-sm font-semibold leading-relaxed ${isDark ? "text-slate-100" : "text-slate-800"}`}>
          Security posture is currently <span className={`font-bold ${isDark ? "text-red-400" : "text-red-600"}`}>Critical ({posture.posture_score ?? 29}/100)</span>.
          The primary risk contributors are <span className={isDark ? "text-slate-200 underline decoration-red-500/50" : "text-slate-900 underline decoration-red-500/50 font-bold"}>active incidents</span> and <span className={isDark ? "text-slate-200 underline decoration-red-500/50" : "text-slate-900 underline decoration-red-500/50 font-bold"}>complete asset exposure</span> across core infrastructure hosts.
          Immediate investigation of critical incidents and prioritized patching of high-severity vulnerabilities on Database-01 and WebServer is recommended.
        </p>
      </div>

      {/* 6 Executive KPI Cards with Tooltips (Part 11 & 12) */}
      <section className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3 md:gap-4">
        <div title="Enterprise health score calculated from active threats, vulnerabilities, and asset criticality">
          <KpiCard
            title="Security Posture"
            value={`${posture.posture_score ?? "--"}/100`}
            statusText={posture.posture_label || "Evaluated"}
            statusType={posture.posture_score >= 75 ? "normal" : "critical"}
            iconType="shield"
          />
        </div>
        <div title="Threats flagged as Critical by AI classification and causal rules">
          <KpiCard
            title="Critical Threats"
            value={(executiveData?.critical_threats ?? 0).toLocaleString()}
            statusText="Immediate Priority"
            statusType="critical"
            iconType="critical"
          />
        </div>
        <div title="Total prioritized security incidents currently in Open or Investigating status">
          <KpiCard
            title="Active Incidents"
            value={(executiveData?.open_incidents ?? 0).toLocaleString()}
            statusText="SOC Queue"
            statusType="moderate"
            iconType="alert"
          />
        </div>
        <div title="Common Vulnerability Scoring System (CVSS ≥ 9.0) security exploits">
          <KpiCard
            title="Critical Vulnerabilities"
            value={(executiveData?.critical_vulnerabilities ?? 0).toLocaleString()}
            statusText="CVSS ≥ 9.0"
            statusType="critical"
            iconType="lock"
          />
        </div>
        <div title="Targeted enterprise hosts and endpoints currently associated with threat events">
          <KpiCard
            title="Affected Assets"
            value={(executiveData?.affected_assets ?? 0).toLocaleString()}
            statusText="Targeted Hosts"
            statusType="normal"
            iconType="activity"
          />
        </div>
        <div title="Total ingested security telemetry logs in historical archive">
          <KpiCard
            title="Monitored Events"
            value={(overviewData?.total_security_events ?? 0).toLocaleString()}
            statusText="Telemetry Volume"
            statusType="normal"
            iconType="lightning"
          />
        </div>
      </section>

      {/* Executive Charts Row 1: Volume Trend Over Time */}
      <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 md:p-5 space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-slate-100">Enterprise Security Volume & Incident Progression</h3>
            <p className="text-xs text-slate-400">Daily telemetry ingestion vs prioritized risk incident correlation</p>
          </div>
          <span className="text-[11px] font-mono text-purple-400 bg-purple-500/10 px-2 py-0.5 rounded border border-purple-500/20">
            Multi-Source Trend
          </span>
        </div>
        <div className="h-[280px]">
          <Line data={trendChartData} options={trendChartOptions} />
        </div>
      </div>

      {/* Executive Charts Row 2: Top Threats + Severity Distribution */}
      <div className="grid gap-5 lg:grid-cols-2">
        {/* Top Threat Categories */}
        <div className={`rounded-xl p-4 md:p-5 space-y-3 border ${
          isDark ? "bg-[#111827] border-[#1F2937]" : "bg-white border-slate-200 shadow-xs"
        }`}>
          <div className="flex items-center justify-between">
            <h3 className={`text-sm font-bold ${isDark ? "text-slate-100" : "text-slate-900"}`}>Top Threat Categories</h3>
            <Link
              to="/dashboard/incidents"
              className={`text-xs font-semibold flex items-center gap-1 ${
                isDark ? "text-blue-400 hover:text-blue-300" : "text-blue-600 hover:text-blue-700"
              }`}
            >
              <span>View Incidents</span>
              <FiArrowRight />
            </Link>
          </div>
          <div className="h-[260px]">
            <Bar data={threatChartData} options={threatChartOptions} />
          </div>
        </div>

        {/* Severity Distribution */}
        <div className={`rounded-xl p-4 md:p-5 space-y-3 border ${
          isDark ? "bg-[#111827] border-[#1F2937]" : "bg-white border-slate-200 shadow-xs"
        }`}>
          <div className="flex items-center justify-between">
            <h3 className={`text-sm font-bold ${isDark ? "text-slate-100" : "text-slate-900"}`}>Threat Severity Distribution</h3>
            <span className={`text-xs ${isDark ? "text-slate-400" : "text-slate-500"}`}>By Raw Event Severity</span>
          </div>
          <div className="h-[260px]">
            <Pie
              data={sevChartData}
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

      {/* Executive Intelligence Row 3: Top Vulnerable Assets + Management Priorities (Part 10) */}
      <div className="grid gap-5 lg:grid-cols-2">
        {/* Top Vulnerable Assets */}
        <div className={`rounded-xl p-4 md:p-5 space-y-3 border ${
          isDark ? "bg-[#111827] border-[#1F2937]" : "bg-white border-slate-200 shadow-xs"
        }`}>
          <div className={`flex items-center justify-between border-b pb-3 ${isDark ? "border-[#1F2937]" : "border-slate-200"}`}>
            <div className="flex items-center gap-2">
              <FiServer className={isDark ? "text-blue-400" : "text-blue-600"} />
              <h3 className={`text-sm font-bold ${isDark ? "text-slate-100" : "text-slate-900"}`}>Top Impacted Enterprise Assets</h3>
            </div>
            <Link
              to="/dashboard/vulnerabilities"
              className={`text-xs font-semibold ${isDark ? "text-blue-400 hover:text-blue-300" : "text-blue-600 hover:text-blue-700"}`}
            >
              All Assets & Vulnerabilities
            </Link>
          </div>

          <div className={`divide-y ${isDark ? "divide-[#1F2937]" : "divide-slate-200"}`}>
            {(executiveData?.top_vulnerable_assets || []).map((asset, idx) => (
              <div key={idx} className="py-2.5 flex items-center justify-between gap-3 text-xs">
                <div className="flex items-center gap-2.5">
                  <span className={`w-5 h-5 rounded flex items-center justify-center font-mono font-bold text-[10px] ${
                    isDark ? "bg-[#1E293B] text-slate-400" : "bg-slate-100 text-slate-700 border border-slate-200"
                  }`}>
                    {idx + 1}
                  </span>
                  <div>
                    <span className={`font-semibold block ${isDark ? "text-slate-200" : "text-slate-900"}`}>{asset.asset_name}</span>
                    <span className={`text-[10px] font-mono ${isDark ? "text-slate-400" : "text-slate-500"}`}>Max CVSS: {asset.max_cvss ? Number(asset.max_cvss).toFixed(1) : "N/A"}</span>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <span className={`text-[11px] ${isDark ? "text-slate-400" : "text-slate-600"}`}>
                    <strong className={`font-mono ${isDark ? "text-red-400" : "text-red-600"}`}>{asset.cve_count || 0}</strong> CVEs
                  </span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold border font-mono ${
                    isDark ? "bg-red-500/20 text-red-300 border-red-500/30" : "bg-red-100 text-red-700 border-red-200"
                  }`}>
                    CVSS {asset.max_cvss}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Management Priorities (Part 10) */}
        <div className={`rounded-xl p-4 md:p-5 space-y-3 border ${
          isDark ? "bg-[#111827] border-[#1F2937]" : "bg-white border-slate-200 shadow-xs"
        }`}>
          <div className={`flex items-center justify-between border-b pb-3 ${isDark ? "border-[#1F2937]" : "border-slate-200"}`}>
            <div className="flex items-center gap-2">
              <FiCheckCircle className={isDark ? "text-emerald-400" : "text-emerald-600"} />
              <h3 className={`text-sm font-bold ${isDark ? "text-slate-100" : "text-slate-900"}`}>Management Priorities & Strategic Roadmap</h3>
            </div>
            <span className={`text-xs font-mono px-2 py-0.5 rounded border ${
              isDark
                ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
                : "text-emerald-700 bg-emerald-50 border-emerald-200"
            }`}>
              CISO Action Plan
            </span>
          </div>

          <div className="space-y-2.5">
            <div className={`rounded-lg p-3 space-y-1 border ${
              isDark ? "bg-[#1E293B]/70 border-[#1F2937]" : "bg-slate-50 border-slate-200"
            }`}>
              <div className="flex items-center justify-between text-xs">
                <span className={`font-bold ${isDark ? "text-slate-200" : "text-slate-900"}`}>1. Address Critical Vulnerabilities</span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                  isDark ? "bg-red-500/20 text-red-300 border-red-500/30" : "bg-red-100 text-red-700 border-red-200"
                }`}>
                  PRIORITY 1
                </span>
              </div>
              <p className={`text-[11px] ${isDark ? "text-slate-300" : "text-slate-600"}`}>
                Critical vulnerabilities require immediate remediation. Prioritize patch deployment for 113 Critical CVEs on Database-01 and WebServer.
              </p>
            </div>

            <div className={`rounded-lg p-3 space-y-1 border ${
              isDark ? "bg-[#1E293B]/70 border-[#1F2937]" : "bg-slate-50 border-slate-200"
            }`}>
              <div className="flex items-center justify-between text-xs">
                <span className={`font-bold ${isDark ? "text-slate-200" : "text-slate-900"}`}>2. Investigate High-Risk Incidents</span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                  isDark ? "bg-red-500/20 text-red-300 border-red-500/30" : "bg-red-100 text-red-700 border-red-200"
                }`}>
                  PRIORITY 2
                </span>
              </div>
              <p className={`text-[11px] ${isDark ? "text-slate-300" : "text-slate-600"}`}>
                High-risk incidents require analyst attention. Focus SOC triage resources on 109 Critical brute force and privilege escalation incidents.
              </p>
            </div>

            <div className={`rounded-lg p-3 space-y-1 border ${
              isDark ? "bg-[#1E293B]/70 border-[#1F2937]" : "bg-slate-50 border-slate-200"
            }`}>
              <div className="flex items-center justify-between text-xs">
                <span className={`font-bold ${isDark ? "text-slate-200" : "text-slate-900"}`}>3. Reduce Asset Exposure</span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                  isDark ? "bg-amber-500/20 text-amber-300 border-amber-500/30" : "bg-amber-100 text-amber-700 border-amber-200"
                }`}>
                  PRIORITY 3
                </span>
              </div>
              <p className={`text-[11px] ${isDark ? "text-slate-300" : "text-slate-600"}`}>
                Prioritize affected enterprise assets. Isolate compromised hosts exhibiting multi-stage attack chains to arrest lateral movement.
              </p>
            </div>

            <div className={`rounded-lg p-3 space-y-1 border ${
              isDark ? "bg-[#1E293B]/70 border-[#1F2937]" : "bg-slate-50 border-slate-200"
            }`}>
              <div className="flex items-center justify-between text-xs">
                <span className={`font-bold ${isDark ? "text-slate-200" : "text-slate-900"}`}>4. Review Unresolved Threats</span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                  isDark ? "bg-amber-500/20 text-amber-300 border-amber-500/30" : "bg-amber-100 text-amber-700 border-amber-200"
                }`}>
                  PRIORITY 4
                </span>
              </div>
              <p className={`text-[11px] ${isDark ? "text-slate-300" : "text-slate-600"}`}>
                Reduce outstanding security risk. Block confirmed malicious IOC indicators at gateway firewalls and perform credential rotation.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
