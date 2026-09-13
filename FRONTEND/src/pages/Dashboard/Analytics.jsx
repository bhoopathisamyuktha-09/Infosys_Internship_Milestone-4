import ErrorBanner from "../../components/ErrorBanner";
import { useAsyncData } from "../../hooks/useAsyncData";
import ThreatDistributionChart from "../../charts/ThreatDistributionChart";
import TopAttackTypesChart from "../../charts/TopAttackTypesChart";
import EventTrendChart from "../../charts/EventTrendChart";
import { getEvents, getThreats } from "../../services/api";

export default function Analytics() {
  const { data, loading, error } = useAsyncData(async () => {
    const [events, threats] = await Promise.all([getEvents(), getThreats()]);
    return { events, threats };
  }, []);

  return (
    <div className="grid gap-5 md:gap-6">
      <h2 className="text-xl md:text-2xl font-extrabold text-slate-100 tracking-tight">Security Analytics</h2>
      {loading && (
        <div className="flex items-center justify-center min-h-[300px]">
          <div className="flex items-center gap-3 text-slate-400 text-sm">
            <span className="h-2 w-2 rounded-full bg-blue-500 animate-ping"></span>
            <span>Loading analytics data...</span>
          </div>
        </div>
      )}
      {error && <ErrorBanner message={error} />}
      {!loading && !error && (
        <>
          <div className="grid gap-5 lg:grid-cols-2">
            <ThreatDistributionChart events={data.events} />
            <TopAttackTypesChart threats={data.threats} />
          </div>
          <EventTrendChart events={data.events} />
        </>
      )}
    </div>
  );
}
