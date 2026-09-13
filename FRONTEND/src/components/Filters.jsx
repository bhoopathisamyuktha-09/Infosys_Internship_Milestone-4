import { SlidersHorizontal, Search } from "lucide-react";
import { EVENT_TYPE_OPTIONS, SEVERITY_OPTIONS } from "../services/api";

export default function Filters({ filters, setFilters }) {
  const update = (key, value) => setFilters((prev) => ({ ...prev, [key]: value }));

  return (
    <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-3.5 md:p-4 shadow-sm flex flex-col gap-3">
      <div className="flex items-center gap-2 text-xs font-bold text-slate-400 uppercase tracking-wider">
        <SlidersHorizontal className="w-3.5 h-3.5 text-blue-400" />
        <span>Filter Events</span>
      </div>

      <div className="flex flex-wrap items-center gap-2.5">
        {/* Severity filter */}
        <div className="flex items-center gap-1">
          {["All", ...SEVERITY_OPTIONS].map((sev) => (
            <button
              key={sev}
              onClick={() => update("severity", sev)}
              className={`px-2.5 py-1 rounded-lg text-xs font-semibold transition-all ${
                filters.severity === sev
                  ? sev === "Critical"
                    ? "bg-red-600 text-white shadow-xs"
                    : "bg-blue-600 text-white shadow-xs"
                  : "bg-[#0B1329] hover:bg-slate-800 text-slate-300 border border-[#1F2937]"
              }`}
            >
              {sev}
            </button>
          ))}
        </div>

        {/* Event type dropdown */}
        <select
          value={filters.eventType}
          onChange={(e) => update("eventType", e.target.value)}
          className="bg-[#0B1329] border border-[#1F2937] text-xs font-medium text-slate-200 rounded-lg px-3 py-1.5 focus:outline-none focus:border-blue-500 cursor-pointer"
        >
          <option value="All" className="bg-[#111827]">All Event Types</option>
          {EVENT_TYPE_OPTIONS.map((t) => (
            <option key={t} value={t} className="bg-[#111827]">{t}</option>
          ))}
        </select>

        {/* Date filter */}
        <input
          type="date"
          value={filters.date}
          onChange={(e) => update("date", e.target.value)}
          className="bg-[#0B1329] border border-[#1F2937] text-xs font-medium text-slate-200 rounded-lg px-3 py-1.5 focus:outline-none focus:border-blue-500 cursor-pointer"
        />

        {/* IP address search */}
        <div className="relative">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search IP address..."
            value={filters.ip}
            onChange={(e) => update("ip", e.target.value)}
            className="bg-[#0B1329] border border-[#1F2937] text-xs font-medium text-slate-200 placeholder:text-slate-500 rounded-lg pl-8 pr-3 py-1.5 focus:outline-none focus:border-blue-500 w-40 md:w-48"
          />
        </div>

        {(filters.severity !== "All" || filters.eventType !== "All" || filters.date || filters.ip) && (
          <button
            onClick={() => setFilters({ severity: "All", eventType: "All", date: "", ip: "" })}
            className="text-xs font-semibold text-blue-400 hover:text-blue-300 underline underline-offset-2 ml-1"
          >
            Clear filters
          </button>
        )}
      </div>
    </div>
  );
}
