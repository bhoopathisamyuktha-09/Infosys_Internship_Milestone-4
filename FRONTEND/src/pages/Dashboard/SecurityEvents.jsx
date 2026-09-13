import { useState } from "react";
import Filters from "../../components/Filters";
import EventTable from "../../components/EventTable";
import ErrorBanner from "../../components/ErrorBanner";
import { useAsyncData } from "../../hooks/useAsyncData";
import { getEvents } from "../../services/api";

export default function SecurityEvents() {
  const [filters, setFilters] = useState({ severity: "All", eventType: "All", date: "", ip: "" });
  const { data: events, loading, error } = useAsyncData(() => getEvents(), []);

  return (
    <div className="grid gap-5">
      <h2 className="text-xl md:text-2xl font-extrabold text-slate-100 tracking-tight">Security Events</h2>
      {loading && (
        <div className="flex items-center justify-center min-h-[300px]">
          <div className="flex items-center gap-3 text-slate-400 text-sm">
            <span className="h-2 w-2 rounded-full bg-blue-500 animate-ping"></span>
            <span>Loading security events...</span>
          </div>
        </div>
      )}
      {error && <ErrorBanner message={error} />}
      {!loading && !error && (
        <>
          <Filters filters={filters} setFilters={setFilters} />
          <EventTable events={events} filters={filters} />
        </>
      )}
    </div>
  );
}
