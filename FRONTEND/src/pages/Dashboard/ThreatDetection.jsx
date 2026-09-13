import { useState, useEffect } from "react";
import KpiCard from "../../components/KpiCard";
import ErrorBanner from "../../components/ErrorBanner";
import ThreatTable from "../../components/ThreatTable";
import AnomalyChart from "../../charts/AnomalyChart";
import ThreatTypeChart from "../../charts/ThreatTypeChart";
import ThreatTrendChart from "../../charts/ThreatTrendChart";
import {
  getPredictions,
  getThreatSummary,
  getModelPerformance,
  getPredictionTrend,
} from "../../services/api";

export default function ThreatDetection() {
  // Global M2 data — fetched ONCE on mount, independent of table pagination
  const [modelPerf, setModelPerf] = useState(null);
  const [trendData, setTrendData] = useState([]);
  const [threatSummary, setThreatSummary] = useState([]);
  const [globalLoading, setGlobalLoading] = useState(true);

  const [predictions, setPredictions] = useState([]);
  const [filteredTotal, setFilteredTotal] = useState(0);
  const [tableLoading, setTableLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filters & Pagination State
  const [filters, setFilters] = useState({
    verdict: "All",
    threat_type: "All",
    severity: "All",
    search: "",
  });
  const [page, setPage] = useState(1);
  const pageSize = 10;

  // A. Fetch global M2 data ONCE on mount
  useEffect(() => {
    async function loadGlobalData() {
      setGlobalLoading(true);
      try {
        const [perfData, trend, summary] = await Promise.all([
          getModelPerformance(),
          getPredictionTrend(),
          getThreatSummary(),
        ]);
        setModelPerf(perfData || null);
        setTrendData(trend || []);
        setThreatSummary(summary || []);
      } catch (err) {
        setError(err.message || "Failed to load global M2 data");
      } finally {
        setGlobalLoading(false);
      }
    }
    loadGlobalData();
  }, []);

  // B. Fetch paginated table data on page/filter/search change
  useEffect(() => {
    async function loadTableData() {
      setTableLoading(true);
      try {
        const skip = (page - 1) * pageSize;
        const predsData = await getPredictions({
          verdict: filters.verdict,
          threat_type: filters.threat_type,
          severity: filters.severity,
          search: filters.search,
          limit: pageSize,
          skip,
        });
        setPredictions(predsData?.items || []);
        setFilteredTotal(predsData?.total || 0);
      } catch (err) {
        setError(err.message || "Failed to load prediction table data");
      } finally {
        setTableLoading(false);
      }
    }
    loadTableData();
  }, [filters.verdict, filters.threat_type, filters.severity, filters.search, page]);

  const handleFilterChange = (newFilters) => {
    setFilters(newFilters);
    setPage(1);
  };

  const handleRefresh = async () => {
    setError(null);
    setGlobalLoading(true);
    setTableLoading(true);
    try {
      const skip = (page - 1) * pageSize;
      const [perfData, trend, summary, predsData] = await Promise.all([
        getModelPerformance(),
        getPredictionTrend(),
        getThreatSummary(),
        getPredictions({
          verdict: filters.verdict,
          threat_type: filters.threat_type,
          severity: filters.severity,
          search: filters.search,
          limit: pageSize,
          skip,
        }),
      ]);
      setModelPerf(perfData || null);
      setTrendData(trend || []);
      setThreatSummary(summary || []);
      setPredictions(predsData?.items || []);
      setFilteredTotal(predsData?.total || 0);
    } catch (err) {
      setError(err.message || "Failed to refresh data");
    } finally {
      setGlobalLoading(false);
      setTableLoading(false);
    }
  };

  // Derive KPI values from global model performance stats
  const distStats = modelPerf?.prediction_distribution_stats || {};
  const totalPreds = distStats.total_predictions ?? 0;
  const anomalyCount = distStats.anomaly_count ?? 0;
  const normalCount = distStats.normal_count ?? (totalPreds - (distStats.suspicious_count ?? 0) - (distStats.critical_count ?? 0));
  const suspiciousCount = distStats.suspicious_count ?? 0;
  const criticalCount = distStats.critical_count ?? 0;
  const avgConf = distStats.average_confidence !== undefined ? `${distStats.average_confidence.toFixed(1)}%` : "0.0%";
  const scoringVer = modelPerf?.hybrid_scorer?.version ? `v${modelPerf.hybrid_scorer.version}` : "v1.1.0";
  const highRiskCount = suspiciousCount + criticalCount;

  const loading = globalLoading || tableLoading;

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-[#111827] border border-[#1F2937] rounded-xl p-5 shadow-sm">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-xl md:text-2xl font-black text-slate-100 tracking-tight">
              AI Threat Detection
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            ML-powered anomaly detection, soft threat classification, and explainable hybrid scoring.
          </p>
        </div>
        <div className="flex items-center gap-3 text-xs">
          <div className="hidden sm:flex items-center gap-2 font-mono text-[11px] text-slate-400 bg-[#0B1329] px-3 py-1.5 rounded-lg border border-[#1F2937]">
            <span>Avg Conf: <strong className="text-blue-400">{avgConf}</strong></span>
            <span className="text-slate-600">|</span>
            <span>Engine: <strong className="text-emerald-400">ONLINE {scoringVer}</strong></span>
          </div>
          <button
            onClick={handleRefresh}
            disabled={loading}
            className="px-3 py-1.5 rounded-lg bg-[#1E293B] hover:bg-slate-800 text-slate-200 border border-[#1F2937] font-semibold transition-all flex items-center gap-1.5"
          >
            <span className={`w-2 h-2 rounded-full ${loading ? "bg-amber-400 animate-ping" : "bg-emerald-400"}`} />
            <span>{loading ? "Refreshing..." : "Refresh Data"}</span>
          </button>
        </div>
      </div>

      {/* Error Alert */}
      {error && <ErrorBanner message={error} />}

      {/* Required 5 Primary M2 KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 xl:grid-cols-5 gap-4">
        <KpiCard
          title="Total Events"
          value={totalPreds.toLocaleString()}
          statusText="Evaluated Predictions"
          statusType="normal"
          iconType="activity"
        />
        <KpiCard
          title="Anomalies Detected"
          value={anomalyCount.toLocaleString()}
          statusText="IF Suspicious Events"
          statusType={anomalyCount > 0 ? "moderate" : "normal"}
          iconType="alert"
        />
        <KpiCard
          title="Normal Events"
          value={normalCount.toLocaleString()}
          statusText="Baseline Activity"
          statusType="normal"
          iconType="lock"
        />
        <KpiCard
          title="High-Risk Events"
          value={highRiskCount.toLocaleString()}
          statusText="Suspicious + Critical Verdicts"
          statusType="moderate"
          iconType="lightning"
        />
        <KpiCard
          title="Critical Threats"
          value={criticalCount.toLocaleString()}
          statusText={criticalCount > 0 ? "Requires Escalation" : "No Escalations"}
          statusType={criticalCount > 0 ? "critical" : "normal"}
          iconType="critical"
        />
      </div>

      {/* Charts Row — uses GLOBAL data only, never paginated table data */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="lg:col-span-1 min-h-[300px]">
          <AnomalyChart distStats={distStats} />
        </div>
        <div className="lg:col-span-1 min-h-[300px]">
          <ThreatTypeChart summary={threatSummary} />
        </div>
        <div className="lg:col-span-1 min-h-[300px]">
          <ThreatTrendChart trendData={trendData} />
        </div>
      </div>

      {/* Threat Predictions Table Section — paginated independently */}
      <div className="space-y-3">
        <ThreatTable
          predictions={predictions}
          totalCount={filteredTotal}
          filters={filters}
          onFilterChange={handleFilterChange}
          page={page}
          pageSize={pageSize}
          onPageChange={setPage}
          loading={tableLoading}
        />
      </div>
    </div>
  );
}
