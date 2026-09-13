import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import {
  FiLayers,
  FiSearch,
  FiChevronLeft,
  FiChevronRight,
  FiRefreshCw,
  FiArrowRight,
} from "react-icons/fi";

import ErrorBanner from "../../components/ErrorBanner";
import KpiCard from "../../components/KpiCard";
import {
  getThreatIntelSummary,
  getThreatIntelIndicators,
  IOC_TYPE_OPTIONS,
  SEVERITY_OPTIONS,
  THREAT_INTEL_STATUS_OPTIONS,
} from "../../services/api";

const SEVERITY_STYLE = {
  Critical: "bg-red-500/20 text-red-400 border-red-500/30",
  High: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  Medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  Low: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
};

const STATUS_STYLE = {
  Malicious: "bg-red-500/20 text-red-300 border-red-500/40 font-bold",
  Suspicious: "bg-amber-500/20 text-amber-300 border-amber-500/40 font-semibold",
  Benign: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40 font-semibold",
  Clean: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40 font-semibold",
};

export default function ThreatIntel() {
  // State
  const [summary, setSummary] = useState(null);
  const [indicators, setIndicators] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filters
  const [iocType, setIocType] = useState("All");
  const [severity, setSeverity] = useState("All");
  const [status, setStatus] = useState("All");
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [page, setPage] = useState(1);
  const pageSize = 25;

  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearch(search);
      setPage(1);
    }, 300);
    return () => clearTimeout(timer);
  }, [search]);

  async function loadData() {
    setLoading(true);
    setError(null);
    try {
      const skip = (page - 1) * pageSize;
      const [sumData, indData] = await Promise.all([
        getThreatIntelSummary(),
        getThreatIntelIndicators({
          indicator_type: iocType !== "All" ? iocType : undefined,
          severity: severity !== "All" ? severity : undefined,
          status: status !== "All" ? status : undefined,
          search: debouncedSearch.trim() || undefined,
          limit: pageSize,
          skip,
        }),
      ]);
      setSummary(sumData);
      setIndicators(indData.items || []);
      setTotal(indData.total || 0);
    } catch (err) {
      setError(err.message || "Failed to load threat intelligence indicators");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
  }, [iocType, severity, status, debouncedSearch, page]);

  const totalPages = Math.ceil(total / pageSize) || 1;

  return (
    <div className="grid gap-5 md:gap-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#111827] border border-[#1F2937] rounded-xl p-4 md:p-5">
        <div>
          <div className="flex items-center gap-2">
            <FiLayers className="text-purple-400 text-xl" />
            <h2 className="text-lg md:text-xl font-bold text-slate-100">Threat Intelligence & IOCs</h2>
            <span className="px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 text-[10px] font-bold font-mono">
              DYNAMIC IOC CORRELATION
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Centralized Indicators of Compromise (IP, domain, hash, CVE) matched against live telemetry and incidents
          </p>
        </div>

        <button
          onClick={loadData}
          disabled={loading}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[#1F2937] bg-[#1E293B] hover:bg-slate-700 text-xs font-semibold text-slate-300 transition-colors"
        >
          <FiRefreshCw className={loading ? "animate-spin" : ""} />
          <span>Refresh Feed</span>
        </button>
      </div>

      {/* Summary KPI Cards */}
      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 md:gap-4">
        <KpiCard
          title="Total Indicators"
          value={(summary?.total_indicators ?? 0).toLocaleString()}
          statusText="Catalog Size"
          statusType="normal"
          iconType="activity"
        />
        <KpiCard
          title="Active Threats"
          value={((summary?.malicious_indicators || 0) + (summary?.suspicious_indicators || 0)).toLocaleString()}
          statusText={`${summary?.malicious_indicators || 0} Malicious, ${summary?.suspicious_indicators || 0} Suspicious`}
          statusType="critical"
          iconType="critical"
        />
        <KpiCard
          title="Matched Events"
          value={(summary?.correlated_events_total ?? 0).toLocaleString()}
          statusText="Correlated Hits"
          statusType="moderate"
          iconType="lightning"
        />
        <KpiCard
          title="Affected Assets"
          value={(summary?.affected_assets_count ?? 0).toLocaleString()}
          statusText="From Live Telemetry"
          statusType="normal"
          iconType="shield"
        />
      </section>

      {/* Filter Toolbar */}
      <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex items-center gap-3 flex-wrap">
          {/* Search Input */}
          <div className="flex items-center rounded-lg border border-[#1F2937] bg-[#1E293B] px-3 py-1.5 focus-within:border-blue-500">
            <FiSearch className="text-slate-400 text-xs mr-2" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search IOC, threat, actor..."
              className="bg-transparent text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none w-48 sm:w-60"
            />
          </div>

          {/* IOC Type Filter */}
          <div className="flex items-center gap-1.5 text-xs">
            <span className="text-slate-400 font-medium">Type:</span>
            <select
              value={iocType}
              onChange={(e) => { setIocType(e.target.value); setPage(1); }}
              className="rounded-lg bg-[#1E293B] border border-[#1F2937] px-2.5 py-1 text-slate-200 focus:outline-none focus:border-blue-500"
            >
              {IOC_TYPE_OPTIONS.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>

          {/* Severity Filter */}
          <div className="flex items-center gap-1.5 text-xs">
            <span className="text-slate-400 font-medium">Severity:</span>
            <select
              value={severity}
              onChange={(e) => { setSeverity(e.target.value); setPage(1); }}
              className="rounded-lg bg-[#1E293B] border border-[#1F2937] px-2.5 py-1 text-slate-200 focus:outline-none focus:border-blue-500"
            >
              <option value="All">All Severities</option>
              {SEVERITY_OPTIONS.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>

          {/* Status Filter */}
          <div className="flex items-center gap-1.5 text-xs">
            <span className="text-slate-400 font-medium">Status:</span>
            <select
              value={status}
              onChange={(e) => { setStatus(e.target.value); setPage(1); }}
              className="rounded-lg bg-[#1E293B] border border-[#1F2937] px-2.5 py-1 text-slate-200 focus:outline-none focus:border-blue-500"
            >
              {THREAT_INTEL_STATUS_OPTIONS.map((st) => (
                <option key={st} value={st}>{st}</option>
              ))}
            </select>
          </div>
        </div>

        <span className="text-xs text-slate-400 font-mono">
          Showing {indicators.length} of {total.toLocaleString()} IOCs
        </span>
      </div>

      {error && <ErrorBanner message={error} onRetry={loadData} />}

      {/* Intelligence Table */}
      <div className="bg-[#111827] border border-[#1F2937] rounded-xl shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-[#1F2937] text-[10px] font-bold text-slate-400 uppercase tracking-wider bg-[#0B1329]">
                <th className="py-2.5 px-3.5">Indicator Value</th>
                <th className="py-2.5 px-3">Type</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Threat Name</th>
                <th className="py-2.5 px-3">Threat Actor</th>
                <th className="py-2.5 px-3 text-center">Threat Count</th>
                <th className="py-2.5 px-3">First Seen</th>
                <th className="py-2.5 px-3">Last Seen</th>
                <th className="py-2.5 px-3 text-center">Confidence</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1F2937]">
              {loading ? (
                <tr>
                  <td colSpan={11} className="py-12 text-center text-slate-400">
                    <div className="flex items-center justify-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-purple-500 animate-ping"></span>
                      <span>Loading threat intelligence records...</span>
                    </div>
                  </td>
                </tr>
              ) : indicators.length === 0 ? (
                <tr>
                  <td colSpan={11} className="py-8 text-center text-slate-400">
                    No threat intelligence indicators found matching selected criteria.
                  </td>
                </tr>
              ) : (
                indicators.map((ioc) => (
                  <tr key={ioc.indicator_id || ioc.indicator_value} className="hover:bg-[#1E293B]/60 transition-colors">
                    <td className="py-2.5 px-3.5 font-mono text-[11px] font-bold text-blue-400">
                      {ioc.indicator_value}
                    </td>
                    <td className="py-2.5 px-3 text-slate-300 uppercase font-mono text-[10px]">
                      {ioc.indicator_type}
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] border ${STATUS_STYLE[ioc.malicious_status] || "border-slate-600 text-slate-400"}`}>
                        {ioc.malicious_status || "Benign"}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-200 font-semibold truncate max-w-[150px]" title={ioc.threat_name}>
                      {ioc.threat_name || "Enterprise Detection"}
                    </td>
                    <td className="py-2.5 px-3 text-slate-300 truncate max-w-[130px]">
                      {ioc.threat_actor || "Unknown"}
                    </td>
                    <td className="py-2.5 px-3 text-center font-mono font-bold text-slate-200">
                      {(ioc.threat_count ?? 0).toLocaleString()}
                    </td>
                    <td className="py-2.5 px-3 text-slate-400 font-mono text-[10px] truncate max-w-[90px]">
                      {ioc.first_seen ? ioc.first_seen.slice(0, 10) : "N/A"}
                    </td>
                    <td className="py-2.5 px-3 text-slate-400 font-mono text-[10px] truncate max-w-[90px]">
                      {ioc.last_seen ? ioc.last_seen.slice(0, 10) : "N/A"}
                    </td>
                    <td className="py-2.5 px-3 text-center font-mono text-slate-300">
                      {ioc.confidence || "N/A"}
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${SEVERITY_STYLE[ioc.severity]}`}>
                        {ioc.severity}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      {ioc.malicious_status === "Malicious" ? (
                        <Link
                          to={`/dashboard/incidents?ioc_status=Malicious`}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-blue-600 hover:bg-blue-700 text-white font-semibold text-[11px] shadow-xs transition-colors"
                        >
                          <span>Correlate</span>
                          <FiArrowRight />
                        </Link>
                      ) : ioc.threat_count > 0 ? (
                        <Link
                          to={`/dashboard/events`}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-blue-600 hover:bg-blue-700 text-white font-semibold text-[11px] shadow-xs transition-colors"
                        >
                          <span>Telemetry</span>
                          <FiArrowRight />
                        </Link>
                      ) : (
                        <span className="text-slate-500 text-[10px]">Clean</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div className="border-t border-[#1F2937] p-3 flex items-center justify-between text-xs bg-[#0B1329]">
          <span className="text-slate-400 font-mono">
            Page {page} of {totalPages}
          </span>
          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1 || loading}
              className="p-1.5 rounded-lg bg-[#1E293B] border border-[#1F2937] text-slate-300 hover:text-white disabled:opacity-40 cursor-pointer"
            >
              <FiChevronLeft />
            </button>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages || loading}
              className="p-1.5 rounded-lg bg-[#1E293B] border border-[#1F2937] text-slate-300 hover:text-white disabled:opacity-40 cursor-pointer"
            >
              <FiChevronRight />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
