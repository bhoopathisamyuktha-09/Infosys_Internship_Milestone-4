import React, { useState, useEffect } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import {
  FiShield,
  FiSearch,
  FiArrowRight,
  FiChevronLeft,
  FiChevronRight,
  FiRefreshCw,
  FiGitCommit,
  FiUser,
  FiServer,
  FiCalendar,
} from "react-icons/fi";

import ErrorBanner from "../../components/ErrorBanner";
import { RiskLevelBadge, PriorityBadge, StatusBadge, RiskScoreBadge } from "../../components/m3/RiskBadge";
import {
  getIncidents,
  RISK_LEVEL_OPTIONS,
  EVENT_TYPE_OPTIONS,
  INCIDENT_STATUS_OPTIONS,
  DEPARTMENT_OPTIONS,
  MITRE_TECHNIQUE_OPTIONS,
  SEVERITY_OPTIONS,
  INCIDENT_IOC_STATUS_OPTIONS,
} from "../../services/api";

export default function PriorityIncidents() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  // State
  const [incidents, setIncidents] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filters & Pagination State (initialized from searchParams if navigated from charts/cards)
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [riskLevel, setRiskLevel] = useState(searchParams.get("risk_level") || "All");
  const [priority, setPriority] = useState(searchParams.get("priority") || "All");
  const [severity, setSeverity] = useState(searchParams.get("severity") || "All");
  const [threatType, setThreatType] = useState(searchParams.get("threat_type") || "All");
  const [department, setDepartment] = useState(searchParams.get("department") || "All");
  const [mitreTechnique, setMitreTechnique] = useState(searchParams.get("mitre_technique") || "All");
  const [cve, setCve] = useState(searchParams.get("cve") || "");
  const [iocStatus, setIocStatus] = useState(searchParams.get("ioc_status") || "All");
  const [startDate, setStartDate] = useState(searchParams.get("start_date") || "");
  const [endDate, setEndDate] = useState(searchParams.get("end_date") || "");
  const [status, setStatus] = useState(searchParams.get("status") || "All");
  const [assetName, setAssetName] = useState(searchParams.get("asset_name") || "");
  const [sortBy, setSortBy] = useState("risk_score");
  const [sortOrder, setSortOrder] = useState("desc");

  async function loadIncidents() {
    setLoading(true);
    setError(null);
    try {
      const skip = (page - 1) * pageSize;
      const res = await getIncidents({
        risk_level: riskLevel !== "All" ? riskLevel : undefined,
        priority: priority !== "All" ? priority : undefined,
        severity: severity !== "All" ? severity : undefined,
        threat_type: threatType !== "All" ? threatType : undefined,
        department: department !== "All" ? department : undefined,
        mitre_technique: mitreTechnique !== "All" ? mitreTechnique : undefined,
        cve: cve.trim() || undefined,
        ioc_status: iocStatus !== "All" ? iocStatus : undefined,
        start_date: startDate || undefined,
        end_date: endDate || undefined,
        asset_name: assetName.trim() || undefined,
        status: status !== "All" ? status : undefined,
        sort_by: sortBy,
        sort_order: sortOrder,
        limit: pageSize,
        skip,
      });
      setIncidents(res.items || []);
      setTotal(res.total || 0);
    } catch (err) {
      setError(err.message || "Failed to load incidents");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadIncidents();
  }, [
    page,
    pageSize,
    riskLevel,
    priority,
    severity,
    threatType,
    department,
    mitreTechnique,
    cve,
    iocStatus,
    startDate,
    endDate,
    status,
    sortBy,
    sortOrder,
  ]);

  const totalPages = Math.ceil(total / pageSize) || 1;

  function handleSearchSubmit(e) {
    e.preventDefault();
    setPage(1);
    loadIncidents();
  }

  function handleResetFilters() {
    setRiskLevel("All");
    setPriority("All");
    setSeverity("All");
    setThreatType("All");
    setDepartment("All");
    setMitreTechnique("All");
    setCve("");
    setIocStatus("All");
    setStartDate("");
    setEndDate("");
    setStatus("All");
    setAssetName("");
    setSortBy("risk_score");
    setSortOrder("desc");
    setPage(1);
  }

  return (
    <div className="grid gap-5 md:gap-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#111827] border border-[#1F2937] rounded-xl p-4 md:p-5">
        <div>
          <div className="flex items-center gap-2">
            <FiShield className="text-blue-400 text-xl" />
            <h2 className="text-lg md:text-xl font-bold text-slate-100">Priority Incidents Queue</h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Deterministic risk-prioritized security incidents with full enrichment & attack chain correlation
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={loadIncidents}
            disabled={loading}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[#1F2937] bg-[#1E293B] hover:bg-slate-700 text-xs font-semibold text-slate-300 transition-colors"
          >
            <FiRefreshCw className={loading ? "animate-spin" : ""} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* Complete Mentor-Required Filter Controls Bar */}
      <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 space-y-3.5">
        <form onSubmit={handleSearchSubmit} className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-8 gap-3">
          {/* 1. Search Asset / Name */}
          <div className="relative sm:col-span-2 lg:col-span-2">
            <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-1 block">
              Asset Search
            </label>
            <div className="flex items-center rounded-lg border border-[#1F2937] bg-[#1E293B] px-2.5 py-1.5 focus-within:border-blue-500">
              <FiSearch className="text-slate-400 text-xs shrink-0 mr-1.5" />
              <input
                type="text"
                value={assetName}
                onChange={(e) => setAssetName(e.target.value)}
                placeholder="Filter asset name..."
                className="w-full bg-transparent text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none"
              />
            </div>
          </div>

          {/* 2. Risk Level Filter */}
          <div>
            <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-1 block">
              Risk Level
            </label>
            <select
              value={riskLevel}
              onChange={(e) => {
                setRiskLevel(e.target.value);
                setPage(1);
              }}
              className="w-full rounded-lg border border-[#1F2937] bg-[#1E293B] px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
            >
              <option value="All">All Risk Levels</option>
              {RISK_LEVEL_OPTIONS.map((lvl) => (
                <option key={lvl} value={lvl}>{lvl}</option>
              ))}
            </select>
          </div>

          {/* 3. Threat Type Filter */}
          <div>
            <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-1 block">
              Threat Type
            </label>
            <select
              value={threatType}
              onChange={(e) => {
                setThreatType(e.target.value);
                setPage(1);
              }}
              className="w-full rounded-lg border border-[#1F2937] bg-[#1E293B] px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
            >
              <option value="All">All Threat Types</option>
              {EVENT_TYPE_OPTIONS.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>

          {/* 4. Department Filter (Mentor Required) */}
          <div>
            <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-1 block">
              Department
            </label>
            <select
              value={department}
              onChange={(e) => {
                setDepartment(e.target.value);
                setPage(1);
              }}
              className="w-full rounded-lg border border-[#1F2937] bg-[#1E293B] px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
            >
              <option value="All">All Departments</option>
              {DEPARTMENT_OPTIONS.map((dep) => (
                <option key={dep} value={dep}>{dep}</option>
              ))}
            </select>
          </div>

          {/* 5. MITRE Technique Filter (Mentor Required) */}
          <div>
            <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-1 block">
              MITRE Technique
            </label>
            <select
              value={mitreTechnique}
              onChange={(e) => {
                setMitreTechnique(e.target.value);
                setPage(1);
              }}
              className="w-full rounded-lg border border-[#1F2937] bg-[#1E293B] px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
            >
              <option value="All">All MITRE Techs</option>
              {MITRE_TECHNIQUE_OPTIONS.map((t) => (
                <option key={t.id} value={t.id}>{t.id} - {t.name}</option>
              ))}
            </select>
          </div>

          {/* 6. Lifecycle Status Filter */}
          <div>
            <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-1 block">
              Status
            </label>
            <select
              value={status}
              onChange={(e) => {
                setStatus(e.target.value);
                setPage(1);
              }}
              className="w-full rounded-lg border border-[#1F2937] bg-[#1E293B] px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
            >
              <option value="All">All Statuses</option>
              {INCIDENT_STATUS_OPTIONS.map((st) => (
                <option key={st} value={st}>{st}</option>
              ))}
            </select>
          </div>

          {/* 7. Sort By Field */}
          <div>
            <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-1 block">
              Sort By
            </label>
            <select
              value={sortBy}
              onChange={(e) => {
                setSortBy(e.target.value);
                setPage(1);
              }}
              className="w-full rounded-lg border border-[#1F2937] bg-[#1E293B] px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
            >
              <option value="risk_score">Enterprise Risk Score (Desc)</option>
              <option value="created_at">Timestamp</option>
              <option value="ml_confidence">AI Detection Confidence</option>
            </select>
          </div>
        </form>

        {/* Date Range & Secondary Filters Row */}
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-3 xl:grid-cols-6 gap-3 pt-2 border-t border-[#1F2937]/70">
          {/* Severity */}
          <div>
            <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-1 block">
              Severity
            </label>
            <select
              value={severity}
              onChange={(e) => {
                setSeverity(e.target.value);
                setPage(1);
              }}
              className="w-full rounded-lg border border-[#1F2937] bg-[#1E293B] px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
            >
              <option value="All">All Severities</option>
              {SEVERITY_OPTIONS.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>

          {/* Threat Intelligence Match */}
          <div>
            <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-1 block" title="Correlated Indicators of Compromise from Threat Intelligence">
              Threat Intel Match
            </label>
            <select
              value={iocStatus}
              onChange={(e) => {
                setIocStatus(e.target.value);
                setPage(1);
              }}
              className="w-full rounded-lg border border-[#1F2937] bg-[#1E293B] px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
            >
              {INCIDENT_IOC_STATUS_OPTIONS.map((st) => (
                <option key={st} value={st}>{st === "All" ? "All IOC Statuses" : st}</option>
              ))}
            </select>
          </div>

          {/* CVE Identifier */}
          <div>
            <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-1 block">
              CVE ID
            </label>
            <input
              type="text"
              value={cve}
              onChange={(e) => {
                setCve(e.target.value);
                setPage(1);
              }}
              placeholder="Search CVE... e.g. CVE-2024-1045"
              className="w-full rounded-lg border border-[#1F2937] bg-[#1E293B] px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* Start Date */}
          <div>
            <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-1 block flex items-center gap-1">
              <FiCalendar className="text-xs text-slate-400" />
              <span>Start Date</span>
            </label>
            <input
              type="date"
              value={startDate}
              onChange={(e) => {
                setStartDate(e.target.value);
                setPage(1);
              }}
              className="w-full rounded-lg border border-[#1F2937] bg-[#1E293B] px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* End Date */}
          <div>
            <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-1 block flex items-center gap-1">
              <FiCalendar className="text-xs text-slate-400" />
              <span>End Date</span>
            </label>
            <input
              type="date"
              value={endDate}
              onChange={(e) => {
                setEndDate(e.target.value);
                setPage(1);
              }}
              className="w-full rounded-lg border border-[#1F2937] bg-[#1E293B] px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* Active Filter Counter & Reset */}
          <div className="flex flex-col justify-end">
            <span className="text-[10px] text-slate-400 mb-1">
              Found <strong className="text-slate-100">{total.toLocaleString()}</strong> incidents
            </span>
            <button
              type="button"
              onClick={handleResetFilters}
              className="px-3 py-1.5 rounded-lg border border-[#1F2937] bg-[#1E293B] hover:bg-slate-700 text-blue-400 hover:text-blue-300 text-xs font-semibold transition-colors cursor-pointer"
            >
              Clear Filters
            </button>
          </div>
        </div>
      </div>

      {error && <ErrorBanner message={error} onRetry={loadIncidents} />}

      {/* Incidents Table */}
      <div className="bg-[#111827] border border-[#1F2937] rounded-xl overflow-hidden shadow-sm">
        {loading ? (
          <div className="flex items-center justify-center py-20">
            <div className="flex items-center gap-3 text-slate-400 text-xs">
              <span className="h-2 w-2 rounded-full bg-blue-500 animate-ping"></span>
              <span>Querying incidents from database...</span>
            </div>
          </div>
        ) : incidents.length === 0 ? (
          <div className="text-center py-16 px-4 space-y-2">
            <FiShield className="text-3xl text-slate-500 mx-auto" />
            <h4 className="text-sm font-semibold text-slate-300">No Incidents Found</h4>
            <p className="text-xs text-slate-400 max-w-sm mx-auto">
              No incidents match the active filter criteria. Try resetting filters or adjusting search parameters.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-[#1F2937] bg-[#1E293B]/60 text-slate-400 font-bold uppercase tracking-wider text-[10px]">
                  <th className="py-3 px-3.5">Score</th>
                  <th className="py-3 px-3.5">Incident ID</th>
                  <th className="py-3 px-3.5">Threat Type</th>
                  <th className="py-3 px-3.5">Risk Level</th>
                  <th className="py-3 px-3.5">Priority</th>
                  <th className="py-3 px-3.5">Asset</th>
                  <th className="py-3 px-3.5">Target User</th>
                  <th className="py-3 px-3.5">Attack Chain</th>
                  <th className="py-3 px-3.5">Status</th>
                  <th className="py-3 px-3.5">Timestamp</th>
                  <th className="py-3 px-3.5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1F2937]">
                {incidents.map((inc) => (
                  <tr
                    key={inc.incident_id}
                    onClick={() => navigate(`/dashboard/incidents/${inc.incident_id}`)}
                    className="hover:bg-[#1E293B]/70 transition-colors cursor-pointer group"
                  >
                    <td className="py-3 px-3.5">
                      <RiskScoreBadge score={inc.risk_score} level={inc.risk_level} size="sm" />
                    </td>
                    <td className="py-3 px-3.5 font-mono font-bold text-blue-400 group-hover:underline">
                      {inc.incident_id}
                    </td>
                    <td className="py-3 px-3.5 font-semibold text-slate-100">
                      {inc.threat_type}
                    </td>
                    <td className="py-3 px-3.5">
                      <RiskLevelBadge level={inc.risk_level} />
                    </td>
                    <td className="py-3 px-3.5">
                      <PriorityBadge priority={inc.priority} />
                    </td>
                    <td className="py-3 px-3.5 text-slate-300 font-medium">
                      <div className="flex flex-col">
                        <div className="flex items-center gap-1.5">
                          <FiServer className="text-[11px] text-slate-400 shrink-0" />
                          <span className="truncate max-w-[120px] font-semibold">{inc.asset_name || "Unknown"}</span>
                        </div>
                        {inc.department && (
                          <span className="text-[10px] text-blue-400/90 font-mono pl-4">{inc.department}</span>
                        )}
                      </div>
                    </td>
                    <td className="py-3 px-3.5 font-mono text-slate-300">
                      <div className="flex items-center gap-1.5">
                        <FiUser className="text-[11px] text-slate-400 shrink-0" />
                        <span>{inc.affected_user || "system"}</span>
                      </div>
                    </td>
                    <td className="py-3 px-3.5">
                      {inc.attack_chain_detected ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 text-[10px] font-semibold">
                          <FiGitCommit className="text-xs" />
                          <span className="truncate max-w-[100px]">{inc.attack_chain_type?.replace(" Chain", "") || "Detected"}</span>
                        </span>
                      ) : (
                        <span className="text-slate-500 font-mono text-[10px]">—</span>
                      )}
                    </td>
                    <td className="py-3 px-3.5">
                      <StatusBadge status={inc.status} />
                    </td>
                    <td className="py-3 px-3.5 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                      {inc.created_at?.substring(0, 16) || "--"}
                    </td>
                    <td className="py-3 px-3.5 text-right">
                      <Link
                        to={`/dashboard/incidents/${inc.incident_id}`}
                        onClick={(e) => e.stopPropagation()}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-blue-600 hover:bg-blue-700 text-white font-semibold text-[11px] shadow-xs transition-colors"
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
        )}

        {/* Pagination Bar */}
        {!loading && incidents.length > 0 && (
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-4 border-t border-[#1F2937] text-xs text-slate-400 bg-[#111827]">
            <div className="flex items-center gap-2">
              <span>Rows per page:</span>
              <select
                value={pageSize}
                onChange={(e) => {
                  setPageSize(Number(e.target.value));
                  setPage(1);
                }}
                className="rounded border border-[#1F2937] bg-[#1E293B] px-2 py-1 text-xs text-slate-200 focus:outline-none"
              >
                <option value={25}>25</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
              </select>
            </div>

            <div className="flex items-center gap-3">
              <span>
                Page <strong className="text-slate-100">{page}</strong> of <strong className="text-slate-100">{totalPages}</strong>
              </span>

              <div className="flex items-center gap-1">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page <= 1}
                  className="p-1.5 rounded border border-[#1F2937] bg-[#1E293B] hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300"
                  aria-label="Previous Page"
                >
                  <FiChevronLeft />
                </button>
                <button
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={page >= totalPages}
                  className="p-1.5 rounded border border-[#1F2937] bg-[#1E293B] hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300"
                  aria-label="Next Page"
                >
                  <FiChevronRight />
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
