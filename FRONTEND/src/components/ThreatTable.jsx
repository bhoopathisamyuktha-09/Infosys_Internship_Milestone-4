import { useState } from "react";
import { Link } from "react-router-dom";
import { ArrowUpDown, Download, Search, ShieldAlert, Filter } from "lucide-react";

const VERDICT_STYLE = {
  Critical: "bg-red-500/20 text-red-400 border-red-500/30",
  Suspicious: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  Normal: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
};

const ANOMALY_STYLE = {
  Suspicious: "bg-red-500/15 text-red-300 border-red-500/20",
  Normal: "bg-slate-700/40 text-slate-400 border-slate-700/50",
};

const SEVERITY_MAP = {
  1: "Low",
  2: "Medium",
  3: "High",
  4: "Critical",
};

const SEVERITY_STYLE = {
  Low: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
  Medium: "text-blue-400 bg-blue-500/10 border-blue-500/20",
  High: "text-amber-400 bg-amber-500/10 border-amber-500/20",
  "High+": "text-orange-400 bg-orange-500/10 border-orange-500/20",
  Critical: "text-red-400 bg-red-500/10 border-red-500/20",
};

export default function ThreatTable({
  predictions = [],
  totalCount = 0,
  filters = { verdict: "All", threat_type: "All", search: "" },
  onFilterChange = () => {},
  page = 1,
  pageSize = 10,
  onPageChange = () => {},
  loading = false,
}) {
  const [sortField, setSortField] = useState("prediction_timestamp");
  const [sortDirection, setSortDirection] = useState("desc");

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDirection(sortDirection === "asc" ? "desc" : "asc");
    } else {
      setSortField(field);
      setSortDirection("desc");
    }
  };

  // Local search filter for quick text lookup
  const searchFiltered = predictions.filter((item) => {
    if (!filters.search) return true;
    const query = filters.search.toLowerCase();
    const eid = (item.event_id || "").toLowerCase();
    const tt = (item.predicted_threat_type || "").toLowerCase();
    const pid = (item.prediction_id || "").toLowerCase();
    return eid.includes(query) || tt.includes(query) || pid.includes(query);
  });

  // Local sorting
  const sorted = [...searchFiltered].sort((a, b) => {
    let aVal = a[sortField];
    let bVal = b[sortField];
    if (typeof aVal === "string") {
      aVal = aVal.toLowerCase();
      bVal = bVal.toLowerCase();
    }
    if (aVal < bVal) return sortDirection === "asc" ? -1 : 1;
    if (aVal > bVal) return sortDirection === "asc" ? 1 : -1;
    return 0;
  });

  const exportCsv = () => {
    const headers = ["Prediction ID", "Event ID", "Event Type", "Verdict", "Confidence Score", "Severity", "Timestamp", "Predicted Threat Type", "Anomaly Label", "Rule Score"];
    const rows = sorted.map((p) => {
      const sevStr = SEVERITY_MAP[p.original_severity] || "Unknown";
      return [
        p.prediction_id,
        p.event_id,
        `"${p.original_event_type || 'Unknown'}"`,
        p.verdict,
        p.confidence_score,
        sevStr,
        p.prediction_timestamp,
        `"${p.predicted_threat_type}"`,
        p.anomaly_label,
        p.rule_score,
      ];
    });
    const csv = [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
    const link = document.createElement("a");
    link.href = encodeURI("data:text/csv;charset=utf-8," + csv);
    link.download = "m2_threat_predictions_export.csv";
    link.click();
  };

  const columns = [
    { key: "event_id", label: "Event ID" },
    { key: "original_event_type", label: "Event Type" },
    { key: "verdict", label: "Prediction" },
    { key: "confidence_score", label: "Confidence" },
    { key: "original_severity", label: "Severity" },
    { key: "prediction_timestamp", label: "Timestamp" },
    { key: "predicted_threat_type", label: "Predicted Threat Type" },
    { key: "anomaly_label", label: "Anomaly Label" },
  ];

  return (
    <div className="bg-[#111827] border border-[#1F2937] rounded-xl shadow-sm overflow-hidden flex flex-col hover:border-slate-700 transition-all duration-200">
      {/* Header & Controls Bar */}
      <div className="p-3.5 border-b border-[#1F2937] bg-[#0B1329] flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-blue-400" />
          <span className="text-xs font-bold text-slate-200">Threat Predictions</span>
          <span className="text-slate-400 font-mono text-[11px] bg-[#111827] px-2 py-0.5 rounded border border-[#1F2937]">
            Showing {sorted.length} of {totalCount.toLocaleString()} predictions
          </span>
        </div>

        {/* Filters & Search */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Search Box */}
          <div className="flex items-center rounded-lg border border-[#1F2937] bg-[#111827] px-2.5 py-1 text-xs">
            <Search className="w-3.5 h-3.5 text-slate-400 shrink-0" />
            <input
              type="text"
              placeholder="Search Event ID / Threat..."
              value={filters.search || ""}
              onChange={(e) => onFilterChange({ ...filters, search: e.target.value })}
              className="ml-1.5 w-36 md:w-48 bg-transparent text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none"
            />
          </div>

          {/* Severity Select */}
          <div className="flex items-center gap-1 bg-[#111827] border border-[#1F2937] rounded-lg px-2 py-1 text-xs">
            <Filter className="w-3 h-3 text-slate-400" />
            <select
              value={filters.severity || "All"}
              onChange={(e) => onFilterChange({ ...filters, severity: e.target.value })}
              className="bg-transparent text-slate-200 focus:outline-none cursor-pointer text-xs"
            >
              <option value="All" className="bg-[#111827]">All Severities</option>
              <option value="Low" className="bg-[#111827]">Low</option>
              <option value="Medium" className="bg-[#111827]">Medium</option>
              <option value="High" className="bg-[#111827]">High</option>
              <option value="Critical" className="bg-[#111827]">Critical</option>
            </select>
          </div>

          {/* Verdict Select */}
          <div className="flex items-center gap-1 bg-[#111827] border border-[#1F2937] rounded-lg px-2 py-1 text-xs">
            <Filter className="w-3 h-3 text-slate-400" />
            <select
              value={filters.verdict || "All"}
              onChange={(e) => onFilterChange({ ...filters, verdict: e.target.value })}
              className="bg-transparent text-slate-200 focus:outline-none cursor-pointer text-xs"
            >
              <option value="All" className="bg-[#111827]">All Verdicts</option>
              <option value="Normal" className="bg-[#111827]">Normal</option>
              <option value="Suspicious" className="bg-[#111827]">Suspicious</option>
              <option value="Critical" className="bg-[#111827]">Critical</option>
            </select>
          </div>

          {/* Export CSV */}
          <button
            onClick={exportCsv}
            disabled={sorted.length === 0}
            className="flex items-center gap-1.5 bg-[#1E293B] hover:bg-slate-800 disabled:opacity-40 text-slate-200 border border-[#1F2937] text-xs font-semibold px-2.5 py-1 rounded-lg transition-all"
          >
            <Download className="w-3.5 h-3.5 text-blue-400" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* Table Body Container with Stable Min-Height */}
      <div className="overflow-x-auto min-h-[440px] relative">
        {loading && (
          <div className="absolute inset-0 bg-[#0F172A]/40 backdrop-blur-[1px] z-10 flex items-center justify-center transition-all duration-200">
            <div className="flex items-center gap-2 bg-[#111827] border border-[#1F2937] rounded-lg px-4 py-2 text-xs font-semibold text-slate-200 shadow-lg">
              <span className="w-4 h-4 rounded-full border-2 border-blue-500 border-t-transparent animate-spin" />
              <span>Updating page data...</span>
            </div>
          </div>
        )}

        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-[#1F2937] text-[10px] font-bold text-slate-400 uppercase tracking-wider bg-[#0B1329]">
              {columns.map((col) => (
                <th
                  key={col.key}
                  className="py-2.5 px-3.5 cursor-pointer hover:text-slate-200 select-none"
                  onClick={() => handleSort(col.key)}
                >
                  <div className="flex items-center gap-1">
                    {col.label} <ArrowUpDown className="w-3 h-3 text-slate-500" />
                  </div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1F2937]">
            {sorted.length === 0 && !loading ? (
              <tr>
                <td colSpan={6} className="py-12 text-center text-xs text-slate-400">
                  No threat predictions available yet.
                </td>
              </tr>
            ) : (
              sorted.map((item) => {
                const tsFormatted = item.prediction_timestamp
                  ? new Date(item.prediction_timestamp).toLocaleString("en-US", {
                      month: "short",
                      day: "2-digit",
                      hour: "2-digit",
                      minute: "2-digit",
                    })
                  : "N/A";

                const score = item.confidence_score || 0;
                const scoreColor =
                  score >= 65 ? "bg-red-500" : score >= 35 ? "bg-amber-500" : "bg-emerald-500";

                const sevStr = SEVERITY_MAP[item.original_severity] || "Unknown";
                const sevStyle = SEVERITY_STYLE[sevStr] || "text-slate-400 bg-slate-800 border-slate-700";

                return (
                  <tr key={item.prediction_id || item.event_id} className="hover:bg-[#1E293B]/60 transition-colors text-xs">
                    {/* Event ID (Clickable Link) */}
                    <td className="py-2.5 px-3.5">
                      <Link
                        to={`/dashboard/events/${encodeURIComponent(item.prediction_id)}`}
                        className="text-blue-400 hover:text-blue-300 font-mono text-xs font-bold hover:underline"
                        title="Click to view explainable AI analysis"
                      >
                        {item.event_id}
                      </Link>
                    </td>

                    {/* Event Type */}
                    <td className="py-2.5 px-3.5 text-slate-300 font-medium">
                      {item.original_event_type || <span className="text-slate-500 italic">Unknown</span>}
                    </td>

                    {/* Verdict */}
                    <td className="py-2.5 px-3.5">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${VERDICT_STYLE[item.verdict] || VERDICT_STYLE.Normal}`}>
                        {item.verdict}
                      </span>
                    </td>

                    {/* Confidence Score Bar */}
                    <td className="py-2.5 px-3.5">
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-2 bg-[#1E293B] rounded-full overflow-hidden border border-[#1F2937]">
                          <div className={`h-full ${scoreColor}`} style={{ width: `${Math.min(100, Math.max(0, score))}%` }} />
                        </div>
                        <span className="font-mono text-xs font-bold text-slate-200">
                          {score.toFixed(1)}%
                        </span>
                      </div>
                    </td>

                    {/* Severity */}
                    <td className="py-2.5 px-3.5">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${sevStyle}`}>
                        {sevStr}
                      </span>
                    </td>

                    {/* Timestamp */}
                    <td className="py-2.5 px-3.5 text-slate-400 font-mono text-[11px] whitespace-nowrap">
                      {tsFormatted}
                    </td>

                    {/* Predicted Threat Type */}
                    <td className="py-2.5 px-3.5 text-slate-200 font-semibold">
                      {item.predicted_threat_type}
                    </td>

                    {/* Anomaly Label */}
                    <td className="py-2.5 px-3.5">
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-medium border ${ANOMALY_STYLE[item.anomaly_label] || ANOMALY_STYLE.Normal}`}>
                        {item.anomaly_label}
                      </span>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      <div className="p-3 border-t border-[#1F2937] bg-[#0B1329] flex items-center justify-between text-xs text-slate-400">
        <span>Page {page} of {Math.max(1, Math.ceil(totalCount / pageSize))}</span>
        <div className="flex gap-2">
          <button
            type="button"
            disabled={page <= 1 || loading}
            onClick={(e) => {
              e.preventDefault();
              onPageChange(page - 1);
            }}
            className="px-3 py-1 rounded-lg bg-[#111827] border border-[#1F2937] hover:bg-slate-800 disabled:opacity-30 disabled:pointer-events-none text-slate-300 font-medium transition-colors cursor-pointer select-none"
          >
            Previous
          </button>
          <button
            type="button"
            disabled={predictions.length < pageSize || loading}
            onClick={(e) => {
              e.preventDefault();
              onPageChange(page + 1);
            }}
            className="px-3 py-1 rounded-lg bg-[#111827] border border-[#1F2937] hover:bg-slate-800 disabled:opacity-30 disabled:pointer-events-none text-slate-300 font-medium transition-colors cursor-pointer select-none"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
