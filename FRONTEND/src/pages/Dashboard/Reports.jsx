import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import {
  FiFileText,
  FiDownload,
  FiShield,
  FiRefreshCw,
  FiCheckCircle,
  FiCalendar,
  FiClock,
  FiArrowRight,
} from "react-icons/fi";

import ErrorBanner from "../../components/ErrorBanner";
import {
  getSecurityReportJson,
  getSecurityReportCsvUrl,
} from "../../services/api";

export default function Reports() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [downloadingJson, setDownloadingJson] = useState(false);

  async function loadReport() {
    setLoading(true);
    setError(null);
    try {
      const data = await getSecurityReportJson();
      setReport(data);
    } catch (err) {
      setError(err.message || "Failed to generate security report");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadReport();
  }, []);

  function handleDownloadJson() {
    if (!report) return;
    setDownloadingJson(true);
    try {
      const jsonStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(report, null, 2));
      const downloadAnchor = document.createElement("a");
      downloadAnchor.setAttribute("href", jsonStr);
      downloadAnchor.setAttribute("download", `security_report_${new Date().toISOString().slice(0, 10)}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
    } finally {
      setDownloadingJson(false);
    }
  }

  if (loading && !report) {
    return (
      <div className="flex items-center justify-center min-h-[450px]">
        <div className="flex items-center gap-3 text-slate-400 text-sm">
          <span className="h-2 w-2 rounded-full bg-blue-500 animate-ping"></span>
          <span>Generating enterprise security compliance report...</span>
        </div>
      </div>
    );
  }

  if (error && !report) {
    return <ErrorBanner message={error} onRetry={loadReport} />;
  }

  const posture = report?.security_posture;

  return (
    <div className="grid gap-5 md:gap-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#111827] border border-[#1F2937] rounded-xl p-4 md:p-5">
        <div>
          <div className="flex items-center gap-2">
            <FiFileText className="text-blue-400 text-xl" />
            <h2 className="text-lg md:text-xl font-bold text-slate-100">Security Reports & Compliance</h2>
            <span className="px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30 text-[10px] font-bold font-mono">
              RFC 4180 COMPLIANT
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Enterprise compliance auditing, incident telemetry exports, and strategic executive briefings
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={loadReport}
            disabled={loading}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[#1F2937] bg-[#1E293B] hover:bg-slate-700 text-xs font-semibold text-slate-300 transition-colors"
          >
            <FiRefreshCw className={loading ? "animate-spin" : ""} />
            <span>Regenerate</span>
          </button>

          <button
            onClick={handleDownloadJson}
            disabled={downloadingJson || !report}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[#1F2937] bg-[#1E293B] hover:bg-slate-700 text-xs font-semibold text-slate-300 transition-colors"
          >
            <FiDownload />
            <span>Download JSON</span>
          </button>

          <a
            href={getSecurityReportCsvUrl()}
            download="sentinelai_incident_report.csv"
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-xs font-semibold text-white shadow transition-colors"
          >
            <FiDownload />
            <span>Download CSV (Full 10K Queue)</span>
          </a>
        </div>
      </div>

      {/* Report Metadata Banner */}
      <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 md:p-5 flex flex-wrap items-center justify-between gap-4 text-xs">
        <div className="flex items-center gap-4 flex-wrap">
          <span className="flex items-center gap-1.5 text-slate-300">
            <FiCalendar className="text-blue-400" />
            Report Date: <strong className="text-slate-100 font-mono">{report?.generated_at ? new Date(report.generated_at).toLocaleDateString() : "N/A"}</strong>
          </span>
          <span className="flex items-center gap-1.5 text-slate-300">
            <FiClock className="text-slate-400" />
            Report ID: <strong className="text-slate-200 font-mono">{report?.report_id || "N/A"}</strong>
          </span>
          <span className="flex items-center gap-1.5 text-slate-300">
            <FiShield className="text-purple-400" />
            Security Posture: <strong className="text-purple-300 font-mono">{posture ? `${posture.posture_score}/100 (${posture.posture_label})` : "N/A"}</strong>
          </span>
        </div>

        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
            <FiCheckCircle className="text-xs" />
            Verified Dynamic Export
          </span>
        </div>
      </div>

      {/* 6 Key Report Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3 md:gap-4">
        <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 space-y-1">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">Total Events</span>
          <span className="text-xl font-extrabold font-mono text-slate-100 block">
            {report?.total_events !== undefined ? report.total_events.toLocaleString() : "..."}
          </span>
          <span className="text-[10px] text-slate-400">Ingested Telemetry</span>
        </div>

        <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 space-y-1">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">Detected Threats</span>
          <span className="text-xl font-extrabold font-mono text-blue-400 block">
            {report?.detected_threats !== undefined ? report.detected_threats.toLocaleString() : "..."}
          </span>
          <span className="text-[10px] text-blue-400/80">ML & Rule Flagged</span>
        </div>

        <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 space-y-1">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">Critical Incidents</span>
          <span className="text-xl font-extrabold font-mono text-red-400 block">
            {report?.critical_incidents !== undefined ? report.critical_incidents.toLocaleString() : "..."}
          </span>
          <span className="text-[10px] text-red-400/80">High Priority SLA</span>
        </div>

        <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 space-y-1">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">High-Risk Assets</span>
          <span className="text-xl font-extrabold font-mono text-orange-400 block">
            {report?.high_risk_assets !== undefined ? report.high_risk_assets.toLocaleString() : "..."}
          </span>
          <span className="text-[10px] text-orange-400/80">Compromised Hosts</span>
        </div>

        <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 space-y-1" title="Common Vulnerability Scoring System (CVSS ≥ 9.0) security exploits">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">Critical Vulnerabilities</span>
          <span className="text-xl font-extrabold font-mono text-amber-400 block">
            {report?.critical_vulnerabilities !== undefined ? report.critical_vulnerabilities.toLocaleString() : "..."}
          </span>
          <span className="text-[10px] text-amber-400/80">Identified Exploits</span>
        </div>

        <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 space-y-1">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block">Attack Chains</span>
          <span className="text-xl font-extrabold font-mono text-purple-400 block">
            {report?.total_attack_chains !== undefined ? report.total_attack_chains.toLocaleString() : "..."}
          </span>
          <span className="text-[10px] text-purple-400/80">Multi-Stage Chains</span>
        </div>
      </div>

      {/* Top Threats & Top MITRE ATT&CK Techniques */}
      <div className="grid gap-5 lg:grid-cols-2">
        {/* Top Threats Table */}
        <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 md:p-5 space-y-3">
          <h3 className="text-sm font-bold text-slate-100 flex items-center justify-between border-b border-[#1F2937] pb-2.5">
            <span>Top Threat Categories</span>
            <span className="text-xs font-normal text-slate-400">By Incident Volume</span>
          </h3>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-[#1F2937] text-[10px] font-bold text-slate-400 uppercase">
                  <th className="py-2">Threat Category</th>
                  <th className="py-2 text-right">Incidents</th>
                  <th className="py-2 text-right">Avg Risk</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1F2937]">
                {(report?.top_threats || []).map((t, idx) => (
                  <tr key={idx} className="hover:bg-[#1E293B]/50">
                    <td className="py-2 text-slate-200 font-semibold">{t.threat_type || t.category || "Unknown"}</td>
                    <td className="py-2 text-right font-mono font-bold text-blue-400">{(t.count ?? 0).toLocaleString()}</td>
                    <td className="py-2 text-right font-mono text-slate-300">{typeof t.avg_risk === "number" ? t.avg_risk.toFixed(1) : "N/A"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Top MITRE ATT&CK Techniques */}
        <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 md:p-5 space-y-3">
          <h3 className="text-sm font-bold text-slate-100 flex items-center justify-between border-b border-[#1F2937] pb-2.5">
            <span>Top MITRE ATT&CK Techniques</span>
            <span className="text-xs font-normal text-slate-400">Adversary Tactics</span>
          </h3>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-[#1F2937] text-[10px] font-bold text-slate-400 uppercase">
                  <th className="py-2">Technique ID</th>
                  <th className="py-2">Name</th>
                  <th className="py-2 text-right">Events</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1F2937]">
                {(report?.top_mitre_techniques || []).map((m, idx) => (
                  <tr key={idx} className="hover:bg-[#1E293B]/50">
                    <td className="py-2 font-mono font-bold text-purple-400">{m.technique_id}</td>
                    <td className="py-2 text-slate-200">{m.technique_name || "Enterprise Technique"}</td>
                    <td className="py-2 text-right font-mono font-bold text-slate-200">{(m.incident_count ?? m.count ?? 0).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Top Vulnerabilities & Strategic Recommendations */}
      <div className="grid gap-5 lg:grid-cols-2">
        {/* Top Vulnerabilities */}
        <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 md:p-5 space-y-3">
          <h3 className="text-sm font-bold text-slate-100 flex items-center justify-between border-b border-[#1F2937] pb-2.5">
            <span>High-Priority Vulnerabilities</span>
            <span className="text-xs font-normal text-slate-400">CVSS v3 Ranked</span>
          </h3>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-[#1F2937] text-[10px] font-bold text-slate-400 uppercase">
                  <th className="py-2">CVE ID</th>
                  <th className="py-2">Vulnerability</th>
                  <th className="py-2 text-right">CVSS</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1F2937]">
                {(report?.top_vulnerabilities || []).slice(0, 5).map((v, idx) => (
                  <tr key={idx} className="hover:bg-[#1E293B]/50">
                    <td className="py-2 font-mono font-bold text-blue-400">{v.cve_id}</td>
                    <td className="py-2 text-slate-200 truncate max-w-[200px]">{v.vulnerability_name || v.name || v.cve_id}</td>
                    <td className="py-2 text-right font-mono font-bold text-red-400">{v.cvss_score}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Strategic Recommendations */}
        <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 md:p-5 space-y-3">
          <h3 className="text-sm font-bold text-slate-100 flex items-center justify-between border-b border-[#1F2937] pb-2.5">
            <span>Strategic Remediation Actions</span>
            <span className="text-xs font-mono text-emerald-400">Action Plan</span>
          </h3>

          <div className="space-y-2.5">
            {(report?.recommendations || report?.strategic_recommendations || []).map((rec, idx) => (
              <div key={idx} className="bg-[#1E293B]/70 border border-[#1F2937] rounded-lg p-3 space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-bold text-slate-200">{rec.action || (typeof rec === "string" ? rec : "Security Action")}</span>
                  {rec.priority && (
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${rec.priority === "P1" || rec.priority === "CRITICAL" ? "bg-red-500/20 text-red-300 border-red-500/30" : "bg-amber-500/20 text-amber-300 border-amber-500/30"}`}>
                      {rec.priority}
                    </span>
                  )}
                </div>
                {rec.target && <p className="text-[11px] text-slate-400 font-mono">Target: {rec.target}</p>}
                {rec.reason && <p className="text-[11px] text-slate-400">{rec.reason}</p>}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Critical Multi-Stage Attack Chains */}
      {report?.attack_chains && report.attack_chains.length > 0 && (
        <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 md:p-5 space-y-3">
          <h3 className="text-sm font-bold text-slate-100 flex items-center justify-between border-b border-[#1F2937] pb-2.5">
            <span>Correlated Attack Chains</span>
            <span className="text-xs font-normal text-slate-400">Multi-Stage Lateral Progression</span>
          </h3>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-[#1F2937] text-[10px] font-bold text-slate-400 uppercase">
                  <th className="py-2">Incident ID</th>
                  <th className="py-2">Attack Chain Pattern</th>
                  <th className="py-2">Affected Asset</th>
                  <th className="py-2 text-right">Risk Score</th>
                  <th className="py-2 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1F2937]">
                {report.attack_chains.map((ac, idx) => (
                  <tr key={idx} className="hover:bg-[#1E293B]/50">
                    <td className="py-2 font-mono font-bold text-blue-400">{ac.incident_id}</td>
                    <td className="py-2 text-slate-200">{ac.attack_chain_type}</td>
                    <td className="py-2 font-mono text-slate-300">{ac.asset_name || "Enterprise Host"}</td>
                    <td className="py-2 text-right font-mono font-bold text-red-400">{ac.risk_score}</td>
                    <td className="py-2 text-right">
                      <Link
                        to={`/dashboard/incidents/${ac.incident_id}`}
                        className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-md bg-blue-600 hover:bg-blue-700 text-white font-semibold text-[11px] shadow-xs transition-colors"
                      >
                        <span>View</span>
                        <FiArrowRight />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
