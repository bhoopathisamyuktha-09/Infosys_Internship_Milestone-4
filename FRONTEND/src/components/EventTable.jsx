import { useState, useMemo } from "react";
import { ArrowUpDown, Download } from "lucide-react";

const SEVERITY_STYLE = {
  Critical: "bg-red-500/20 text-red-400 border-red-500/30",
  High: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  Medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  Low: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
};

const STATUS_STYLE = {
  Open: "bg-red-500/15 text-red-300 border-red-500/20",
  Investigating: "bg-amber-500/15 text-amber-300 border-amber-500/20",
  Resolved: "bg-emerald-500/15 text-emerald-300 border-emerald-500/20",
  Closed: "bg-slate-700/40 text-slate-400 border-slate-700/50",
};

export default function EventTable({ events, filters }) {
  const [sortField, setSortField] = useState("timestamp");
  const [sortDirection, setSortDirection] = useState("desc");
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 10; // Slightly increased page size for compact rows

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDirection(sortDirection === "asc" ? "desc" : "asc");
    } else {
      setSortField(field);
      setSortDirection("desc");
    }
  };

  const filtered = useMemo(() => {
    return events.filter((evt) => {
      const matchesSeverity = filters.severity === "All" || evt.severity === filters.severity;
      const matchesType = filters.eventType === "All" || evt.eventType === filters.eventType;
      const matchesIp = filters.ip === "" || evt.sourceIP.includes(filters.ip);
      const matchesDate = filters.date === "" || evt.timestamp.slice(0, 10) === filters.date;
      return matchesSeverity && matchesType && matchesIp && matchesDate;
    });
  }, [events, filters]);

  const sorted = useMemo(() => {
    return [...filtered].sort((a, b) => {
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
  }, [filtered, sortField, sortDirection]);

  const totalPages = Math.max(1, Math.ceil(sorted.length / pageSize));
  const page = Math.min(currentPage, totalPages);
  const paginated = sorted.slice((page - 1) * pageSize, page * pageSize);

  const exportCsv = () => {
    const headers = ["Event ID", "Time", "Event Type", "Severity", "Source IP", "Status", "MITRE Technique"];
    const rows = sorted.map((e) => [e.id, e.time, e.eventType, e.severity, e.sourceIP, e.status, e.mitre.id]);
    const csv = [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
    const link = document.createElement("a");
    link.href = encodeURI("data:text/csv;charset=utf-8," + csv);
    link.download = "security_events_export.csv";
    link.click();
  };

  const columns = [
    { key: "time", label: "Time" },
    { key: "eventType", label: "Event Type" },
    { key: "severity", label: "Severity" },
    { key: "sourceIP", label: "Source IP" },
    { key: "status", label: "Status" },
    { key: "mitre", label: "MITRE" },
  ];

  return (
    <div className="bg-[#111827] border border-[#1F2937] rounded-xl shadow-sm overflow-hidden flex flex-col hover:border-slate-700 transition-all duration-200">
      <div className="p-3.5 border-b border-[#1F2937] bg-[#0B1329] flex items-center justify-between">
        <span className="text-xs font-bold text-slate-200 flex items-center gap-2">
          <span>Security Events</span>
          <span className="text-slate-400 font-mono text-[11px] bg-[#111827] px-2 py-0.5 rounded border border-[#1F2937]">
            {sorted.length} records
          </span>
        </span>
        <button
          onClick={exportCsv}
          className="flex items-center gap-1.5 bg-[#1E293B] hover:bg-slate-800 text-slate-200 border border-[#1F2937] text-xs font-semibold px-2.5 py-1 rounded-lg transition-all"
        >
          <Download className="w-3.5 h-3.5 text-blue-400" />
          <span>Export CSV</span>
        </button>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-[#1F2937] text-[10px] font-bold text-slate-400 uppercase tracking-wider bg-[#0B1329]">
              {columns.map((col) => (
                <th
                  key={col.key}
                  className={`py-2.5 px-3.5 ${col.key !== "mitre" ? "cursor-pointer hover:text-slate-200 select-none" : ""}`}
                  onClick={() => col.key !== "mitre" && handleSort(col.key)}
                >
                  <div className="flex items-center gap-1">
                    {col.label} {col.key !== "mitre" && <ArrowUpDown className="w-3 h-3 text-slate-500" />}
                  </div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1F2937]">
            {paginated.map((evt) => (
              <tr key={evt.id} className="hover:bg-[#1E293B]/60 transition-colors text-xs">
                <td className="py-2 px-3.5 text-slate-400 font-mono text-[11px]">{evt.time}</td>
                <td className="py-2 px-3.5 text-slate-200 font-semibold">{evt.eventType}</td>
                <td className="py-2 px-3.5">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${SEVERITY_STYLE[evt.severity]}`}>
                    {evt.severity}
                  </span>
                </td>
                <td className="py-2 px-3.5 text-slate-300 font-mono text-[11px]">{evt.sourceIP}</td>
                <td className="py-2 px-3.5">
                  <span className={`px-2 py-0.5 rounded-full text-[10px] font-medium border ${STATUS_STYLE[evt.status]}`}>
                    {evt.status}
                  </span>
                </td>
                <td className="py-2 px-3.5">
                  <span
                    className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-slate-800 text-blue-300 border border-slate-700"
                    title={`${evt.mitre.technique} (${evt.mitre.tactic})`}
                  >
                    {evt.mitre.id}
                  </span>
                </td>
              </tr>
            ))}
            {paginated.length === 0 && (
              <tr>
                <td colSpan={6} className="py-8 text-center text-xs text-slate-500">
                  No events match the current filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="p-2.5 border-t border-[#1F2937] bg-[#0B1329] flex items-center justify-between text-xs text-slate-400">
        <span>Page {page} of {totalPages}</span>
        <div className="flex gap-1.5">
          <button
            disabled={page <= 1}
            onClick={() => setCurrentPage((p) => p - 1)}
            className="px-2.5 py-1 rounded-lg bg-[#111827] border border-[#1F2937] hover:bg-slate-800 disabled:opacity-30 disabled:pointer-events-none text-slate-300"
          >
            Prev
          </button>
          <button
            disabled={page >= totalPages}
            onClick={() => setCurrentPage((p) => p + 1)}
            className="px-2.5 py-1 rounded-lg bg-[#111827] border border-[#1F2937] hover:bg-slate-800 disabled:opacity-30 disabled:pointer-events-none text-slate-300"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
