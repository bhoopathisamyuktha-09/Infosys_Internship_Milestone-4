import React from "react";
import { FiServer, FiShield, FiAlertTriangle, FiCpu, FiLayers, FiUser } from "react-icons/fi";

export default function SecurityIntelligenceCard({ incident }) {
  if (!incident) return null;

  const {
    asset_id,
    asset_name,
    affected_user,
    cvss_score,
    ioc_status,
    ioc_value,
    ioc_matched_field,
    ioc_type,
    ioc_confidence,
    ioc_severity,
    threat_name,
    threat_actor,
    mitre_techniques = [],
    ml_confidence,
    anomaly_score,
  } = incident;

  const isMalicious = ioc_status === "Malicious" || Boolean(ioc_value);
  const matchedFieldLabel =
    ioc_matched_field === "source_ip"
      ? "Source IP"
      : ioc_matched_field === "destination_ip"
      ? "Destination IP"
      : ioc_matched_field || "Indicator";

  return (
    <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-5 md:p-6 space-y-4">
      <div className="border-b border-[#1F2937] pb-3">
        <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
          <FiLayers className="text-purple-400" />
          <span>Integrated Security Intelligence</span>
        </h3>
        <p className="text-xs text-slate-400 mt-0.5">
          Contextual signals aggregated across Asset, Vulnerability, Threat Intel, and MITRE feeds
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* 1. Target Asset Information */}
        <div className="bg-[#1E293B] border border-[#1F2937] rounded-lg p-4 space-y-2.5">
          <div className="flex items-center gap-2 text-xs font-bold text-slate-200">
            <FiServer className="text-blue-400" />
            <span>Asset Context</span>
          </div>
          <div className="space-y-1.5 text-xs">
            <div className="flex justify-between">
              <span className="text-slate-400">Asset Name:</span>
              <span className="font-semibold text-slate-100">{asset_name || "Unknown Asset"}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Asset ID:</span>
              <span className="font-mono text-slate-200 font-medium">{asset_id || "AST-N/A"}</span>
            </div>
            {incident.department && (
              <div className="flex justify-between">
                <span className="text-slate-400">Department:</span>
                <span className="text-blue-400 font-semibold">{incident.department}</span>
              </div>
            )}
            <div className="flex justify-between">
              <span className="text-slate-400">Target User:</span>
              <span className="font-mono text-slate-200 flex items-center gap-1">
                <FiUser className="text-[10px] text-slate-400" />
                {affected_user || "System/Root"}
              </span>
            </div>
          </div>
        </div>

        {/* 2. Vulnerability / CVE */}
        <div className="bg-[#1E293B] border border-[#1F2937] rounded-lg p-4 space-y-2.5">
          <div className="flex items-center gap-2 text-xs font-bold text-slate-200">
            <FiAlertTriangle className="text-orange-400" />
            <span>Vulnerability Context</span>
          </div>
          <div className="space-y-1.5 text-xs">
            <div className="flex justify-between">
              <span className="text-slate-400">CVSS Score:</span>
              <span className={`font-mono font-bold ${cvss_score >= 9.0 ? "text-red-400" : cvss_score >= 7.0 ? "text-orange-400" : "text-slate-200"}`}>
                {cvss_score !== null && cvss_score !== undefined ? cvss_score.toFixed(1) : "N/A"}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">CVE Identifier:</span>
              <span className="font-mono text-slate-200 font-semibold">
                {incident.reasons?.find((r) => r.includes("CVE-"))?.match(/CVE-\d{4}-\d+/)?.[0] || (cvss_score ? "Associated" : "None")}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Severity Rating:</span>
              <span className="text-slate-200 font-semibold">
                {cvss_score >= 9.0 ? "Critical" : cvss_score >= 7.0 ? "High" : cvss_score >= 4.0 ? "Medium" : "Low"}
              </span>
            </div>
          </div>
        </div>

        {/* 3. Threat Intelligence — all fields from backend, no hardcoding */}
        <div className="bg-[#1E293B] border border-[#1F2937] rounded-lg p-4 space-y-2.5">
          <div className="flex items-center gap-2 text-xs font-bold text-slate-200">
            <FiShield className={isMalicious ? "text-red-400" : "text-emerald-400"} />
            <span>Threat Intelligence</span>
          </div>
          {isMalicious ? (
            <div className="space-y-1.5 text-xs">
              <div className="flex justify-between items-center">
                <span className="text-slate-400" title="Correlated Indicators of Compromise from Threat Intelligence">
                  Threat Intelligence Match:
                </span>
                <span className="font-semibold px-1.5 py-0.5 rounded text-[10px] bg-red-500/20 text-red-300 border border-red-500/30">
                  Malicious
                </span>
              </div>
              {ioc_value && (
                <div className="flex justify-between items-center">
                  <span className="text-slate-400">Matched {matchedFieldLabel}:</span>
                  <span className="font-mono text-red-300 font-bold text-[11px] truncate max-w-[125px]" title={ioc_value}>
                    {ioc_value}
                  </span>
                </div>
              )}
              {threat_name && (
                <div className="flex justify-between gap-2">
                  <span className="text-slate-400 shrink-0">Threat Name:</span>
                  <span className="text-amber-300 font-medium text-right truncate max-w-[120px]" title={threat_name}>
                    {threat_name}
                  </span>
                </div>
              )}
              <div className="flex justify-between">
                <span className="text-slate-400">Threat Actor:</span>
                <span className="text-slate-200 font-medium truncate max-w-[120px]">
                  {threat_actor || "Unknown"}
                </span>
              </div>
              {ioc_type && (
                <div className="flex justify-between">
                  <span className="text-slate-400">IOC Type:</span>
                  <span className="text-slate-300 font-mono text-[11px]">{ioc_type}</span>
                </div>
              )}
              {ioc_confidence && (
                <div className="flex justify-between">
                  <span className="text-slate-400">Confidence:</span>
                  <span className={`font-semibold text-[11px] ${ioc_confidence === "Critical" ? "text-red-400" : ioc_confidence === "High" ? "text-orange-400" : "text-slate-300"}`}>
                    {ioc_confidence}
                  </span>
                </div>
              )}
              {ioc_severity && (
                <div className="flex justify-between">
                  <span className="text-slate-400">IOC Severity:</span>
                  <span className={`font-semibold text-[11px] ${ioc_severity === "Critical" ? "text-red-400" : ioc_severity === "High" ? "text-orange-400" : "text-slate-300"}`}>
                    {ioc_severity}
                  </span>
                </div>
              )}
            </div>
          ) : (
            <div className="space-y-2 text-xs pt-0.5">
              <div className="flex justify-between items-center">
                <span className="text-slate-400">IOC Status:</span>
                <span className="font-semibold px-1.5 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                  Clean
                </span>
              </div>
              <div className="rounded-md bg-[#111827]/80 p-2.5 border border-[#1F2937] space-y-1">
                <div className="text-[11px] font-semibold text-slate-300 flex items-center gap-1.5">
                  <FiShield className="text-emerald-400 text-xs shrink-0" />
                  <span>No Threat Intel Match</span>
                </div>
                <p className="text-[10px] text-slate-400 leading-relaxed">
                  Observed network indicators show no active malicious reputational matches across intelligence feeds.
                </p>
              </div>
            </div>
          )}
        </div>

        {/* 4. MITRE & AI Detection Context */}
        <div className="bg-[#1E293B] border border-[#1F2937] rounded-lg p-4 space-y-2.5">
          <div className="flex items-center gap-2 text-xs font-bold text-slate-200">
            <FiCpu className="text-purple-400" />
            <span title="Adversary behavior mapped to the MITRE ATT&CK framework and ML anomaly scoring">MITRE & AI Context</span>
          </div>
          <div className="space-y-1.5 text-xs">
            <div className="flex justify-between">
              <span className="text-slate-400" title="Confidence assigned by the threat detection model">AI Detection Confidence:</span>
              <span className="font-mono font-bold text-blue-400">{ml_confidence ? `${ml_confidence}%` : "--"}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Anomaly Signal:</span>
              <span className="font-mono font-semibold text-amber-400">{anomaly_score !== null && anomaly_score !== undefined ? anomaly_score : "--"}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-slate-400">MITRE Tech:</span>
              <div className="flex gap-1 flex-wrap justify-end">
                {mitre_techniques.length > 0 ? (
                  mitre_techniques.map((t) => (
                    <span key={t} className="font-mono text-[10px] px-1.5 py-0.2 rounded bg-[#111827] text-purple-300 border border-[#1F2937]">
                      {t}
                    </span>
                  ))
                ) : (
                  <span className="text-slate-500 text-[11px]">None</span>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
