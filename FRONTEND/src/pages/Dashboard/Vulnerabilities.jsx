import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import {
  FiLock,
  FiSearch,
  FiCheckCircle,
  FiXCircle,
  FiChevronLeft,
  FiChevronRight,
  FiRefreshCw,
  FiArrowRight,
} from "react-icons/fi";

import ErrorBanner from "../../components/ErrorBanner";
import KpiCard from "../../components/KpiCard";
import {
  getVulnerabilitiesSummary,
  getPaginatedVulnerabilities,
  SEVERITY_OPTIONS,
  PATCH_OPTIONS,
} from "../../services/api";

const SEVERITY_STYLE = {
  Critical: "bg-red-500/20 text-red-400 border-red-500/30",
  High: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  Medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  Low: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
};

export default function Vulnerabilities() {
  const [summary, setSummary] = useState(null);
  const [vulns, setVulns] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filters
  const [severity, setSeverity] = useState("All");
  const [patchAvailable, setPatchAvailable] = useState("All");
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
      const [sumData, listData] = await Promise.all([
        getVulnerabilitiesSummary(),
        getPaginatedVulnerabilities({
          severity: severity !== "All" ? severity : undefined,
          patch_available: patchAvailable !== "All" ? patchAvailable : undefined,
          search: debouncedSearch.trim() || undefined,
          limit: pageSize,
          skip,
        }),
      ]);
      setSummary(sumData);
      setVulns(listData.items || []);
      setTotal(listData.total || 0);
    } catch (err) {
      setError(err.message || "Failed to load vulnerabilities data");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();
  }, [severity, patchAvailable, debouncedSearch, page]);

  const totalPages = Math.ceil(total / pageSize) || 1;

  return (
    <div className="grid gap-5 md:gap-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#111827] border border-[#1F2937] rounded-xl p-4 md:p-5">
        <div>
          <div className="flex items-center gap-2">
            <FiLock className="text-orange-400 text-xl" />
            <h2 className="text-lg md:text-xl font-bold text-slate-100">System Vulnerabilities (CVE Intelligence)</h2>
            <span className="px-2 py-0.5 rounded bg-orange-500/20 text-orange-300 border border-orange-500/30 text-[10px] font-bold font-mono">
              CVSS v3 RATED
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Enterprise vulnerability exposure tracking, CVSS severity ratings, and host remediation status
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
          title="Critical Vulnerabilities"
          value={(summary?.critical_cves ?? 0).toLocaleString()}
          statusText="CVSS 9.0 – 10.0"
          statusType="critical"
          iconType="critical"
        />
        <KpiCard
          title="High Vulnerabilities"
          value={(summary?.high_cves ?? 0).toLocaleString()}
          statusText="CVSS 7.0 – 8.9"
          statusType="moderate"
          iconType="alert"
        />
        <KpiCard
          title="Medium Vulnerabilities"
          value={(summary?.medium_cves ?? 0).toLocaleString()}
          statusText="CVSS 4.0 – 6.9"
          statusType="normal"
          iconType="lightning"
        />
        <KpiCard
          title="Affected Assets"
          value={(summary?.affected_assets_count ?? 0).toLocaleString()}
          statusText={`${summary?.total_vulnerabilities ?? 0} Total CVE Records`}
          statusType="normal"
          iconType="lock"
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
              placeholder="Filter CVE ID, asset, or name..."
              className="bg-transparent text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none w-48 sm:w-60"
            />
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

          {/* Patch Status Filter */}
          <div className="flex items-center gap-1.5 text-xs">
            <span className="text-slate-400 font-medium">Patch:</span>
            <select
              value={patchAvailable}
              onChange={(e) => { setPatchAvailable(e.target.value); setPage(1); }}
              className="rounded-lg bg-[#1E293B] border border-[#1F2937] px-2.5 py-1 text-slate-200 focus:outline-none focus:border-blue-500"
            >
              {PATCH_OPTIONS.map((p) => (
                <option key={p} value={p}>
                  {p === "All" ? "All Patches" : p === "Yes" ? "Patch Available" : "No Patch"}
                </option>
              ))}
            </select>
          </div>
        </div>

        <span className="text-xs text-slate-400 font-mono">
          Showing {vulns.length} of {total.toLocaleString()} Vulnerabilities
        </span>
      </div>

      {error && <ErrorBanner message={error} onRetry={loadData} />}

      {/* Vulnerabilities Table */}
      <div className="bg-[#111827] border border-[#1F2937] rounded-xl shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-[#1F2937] text-[10px] font-bold text-slate-400 uppercase tracking-wider bg-[#0B1329]">
                <th className="py-2.5 px-3.5">CVE Identifier</th>
                <th className="py-2.5 px-3">Vulnerability Name</th>
                <th className="py-2.5 px-3">Affected Asset</th>
                <th className="py-2.5 px-3 text-center">CVSS Score</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Patch Availability</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1F2937]">
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-400">
                    <div className="flex items-center justify-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-orange-500 animate-ping"></span>
                      <span>Loading vulnerability records...</span>
                    </div>
                  </td>
                </tr>
              ) : vulns.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-400">
                    No vulnerabilities found matching selected criteria.
                  </td>
                </tr>
              ) : (
                vulns.map((v) => (
                  <tr key={v.vulnerability_id || v.cve_id} className="hover:bg-[#1E293B]/60 transition-colors">
                    <td className="py-2.5 px-3.5 font-mono text-[11px] font-bold text-blue-400">
                      {v.cve_id}
                    </td>
                    <td className="py-2.5 px-3 text-slate-200 font-semibold truncate max-w-[200px]" title={v.vulnerability_name}>
                      {v.vulnerability_name}
                    </td>
                    <td className="py-2.5 px-3 text-slate-300 font-medium">
                      {v.affected_asset}
                    </td>
                    <td className="py-2.5 px-3 text-center font-mono font-bold">
                      <span className={v.cvss_score >= 9.0 ? "text-red-400" : v.cvss_score >= 7.0 ? "text-orange-400" : "text-slate-200"}>
                        {typeof v.cvss_score === "number" ? v.cvss_score.toFixed(1) : v.cvss_score}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${SEVERITY_STYLE[v.severity]}`}>
                        {v.severity}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-300">
                      {v.status}
                    </td>
                    <td className="py-2.5 px-3">
                      {v.patch_available === "Yes" || v.patch_available === true ? (
                        <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400 font-medium">
                          <FiCheckCircle className="text-xs" />
                          <span>Available</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-[11px] text-slate-400">
                          <FiXCircle className="text-xs text-slate-500" />
                          <span>No Patch</span>
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <Link
                        to={`/dashboard/incidents?cve=${encodeURIComponent(v.cve_id)}`}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-blue-600 hover:bg-blue-700 text-white font-semibold text-[11px] shadow-xs transition-colors"
                      >
                        <span>Incidents</span>
                        <FiArrowRight />
                      </Link>
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
