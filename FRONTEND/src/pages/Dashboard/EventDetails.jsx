import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import {
  ArrowLeft,
  ShieldAlert,
  Cpu,
  FileText,
  Activity,
  Layers,
  CheckCircle2,
  AlertTriangle,
  Server,
  User,
  Clock,
  Globe,
  Database,
} from "lucide-react";

import ConfidenceCard from "../../components/ConfidenceCard";
import ErrorBanner from "../../components/ErrorBanner";
import { getPredictionById, getEventById } from "../../services/api";

const SEVERITY_BADGE = {
  Critical: "bg-red-500/20 text-red-300 border-red-500/30",
  High: "bg-orange-500/20 text-orange-300 border-orange-500/30",
  Medium: "bg-amber-500/20 text-amber-300 border-amber-500/30",
  Low: "bg-emerald-500/20 text-emerald-300 border-emerald-500/30",
};

export default function EventDetails() {
  const { id: predictionId } = useParams();
  const [prediction, setPrediction] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    async function loadData() {
      if (!predictionId) return;
      setLoading(true);
      setError(null);
      try {
        const data = await getPredictionById(predictionId);
        setPrediction(data);
      } catch (err) {
        try {
          const rawEvt = await getEventById(predictionId);
          setPrediction({
            event_id: rawEvt.event_id,
            prediction_id: `PRED-${rawEvt.event_id}`,
            prediction_timestamp: rawEvt.timestamp,
            verdict: rawEvt.severity === "Critical" ? "Critical" : rawEvt.severity === "High" ? "Suspicious" : "Normal",
            confidence_score: Math.round((rawEvt.threat_confidence || 0.7) * 100),
            predicted_threat_type: rawEvt.event_type || "Security Alert",
            anomaly_label: rawEvt.severity === "Critical" ? "Anomaly" : "Normal",
            anomaly_score: rawEvt.risk_score || 50,
            rule_score: 50,
            source_event: rawEvt,
            reasons: [`Raw telemetry event observed for user ${rawEvt.username || "system"}`],
          });
        } catch {
          setError(err.message || "Failed to load prediction details");
        }
      } finally {
        setLoading(false);
      }
    }

    loadData();
  }, [predictionId]);

  if (loading) {
    return (
      <div className="py-20 flex flex-col items-center justify-center space-y-3">
        <div className="w-8 h-8 rounded-full border-3 border-blue-500 border-t-transparent animate-spin" />
        <p className="text-xs text-slate-400 font-medium">Fetching threat prediction details...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="space-y-4">
        <Link
          to="/dashboard/detection"
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-blue-400 hover:text-blue-300 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Threat Detection</span>
        </Link>
        <ErrorBanner message={error} />
      </div>
    );
  }

  if (!prediction) {
    return (
      <div className="space-y-4">
        <Link
          to="/dashboard/detection"
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-blue-400 hover:text-blue-300 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Threat Detection</span>
        </Link>
        <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-8 text-center text-xs text-slate-400">
          Prediction not found for ID '{predictionId}'.
        </div>
      </div>
    );
  }

  const {
    event_id,
    prediction_id,
    prediction_timestamp,
    verdict,
    confidence_score = 0,
    predicted_threat_type = "Unknown",
    rf_top_probability = 0,
    rf_confidence_note = "low",
    anomaly_label = "Normal",
    anomaly_score = 0,
    anomaly_score_raw = 0,
    rule_score = 0,
    triggered_rules = [],
    reasons = [],
    model_signals = {},
    model_metadata = {},
    source_event = {},
  } = prediction;

  const srcEvent = source_event || {};

  const tsFormatted = prediction_timestamp
    ? new Date(prediction_timestamp).toLocaleString("en-US", {
        month: "short",
        day: "2-digit",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        timeZoneName: "short",
      })
    : "N/A";

  const eventTsFormatted = srcEvent.timestamp
    ? new Date(srcEvent.timestamp).toLocaleString("en-US", {
        month: "short",
        day: "2-digit",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      })
    : tsFormatted;

  return (
    <div className="space-y-6">
      {/* Top Back Nav & Header */}
      <div className="space-y-3">
        <Link
          to="/dashboard/detection"
          className="inline-flex items-center gap-1.5 text-xs font-semibold text-blue-400 hover:text-blue-300 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Threat Detection</span>
        </Link>

        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-[#111827] border border-[#1F2937] rounded-xl p-5 shadow-sm">
          <div>
            <div className="flex items-center gap-3">
              <span className="text-xs font-mono font-bold bg-blue-500/15 text-blue-400 border border-blue-500/30 px-2.5 py-1 rounded-lg">
                Event {event_id}
              </span>
              <span className="text-xs font-mono text-slate-400">
                {prediction_id}
              </span>
            </div>
            <h2 className="text-xl md:text-2xl font-black text-slate-100 tracking-tight mt-2">
              Security Event Investigation & AI Threat Analysis
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Evaluated at <span className="font-mono text-slate-300">{tsFormatted}</span>
            </p>
          </div>
        </div>
      </div>

      {/* SECTION A: Original Security Event Details */}
      <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex items-center justify-between border-b border-[#1F2937] pb-3">
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <Server className="w-4 h-4 text-blue-400" />
            <span>Section A: Original Security Event Telemetry</span>
          </h3>
          <span className="text-xs font-mono text-slate-400 bg-[#0B1329] px-2 py-0.5 rounded border border-[#1F2937]">
            Source telemetry
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4 text-xs">
          <div className="bg-[#0B1329] p-3 rounded-lg border border-[#1F2937]">
            <span className="text-slate-400 block mb-1 flex items-center gap-1.5">
              <Database className="w-3.5 h-3.5 text-slate-500" />
              Event ID
            </span>
            <span className="font-mono font-bold text-blue-400">{event_id}</span>
          </div>

          <div className="bg-[#0B1329] p-3 rounded-lg border border-[#1F2937]">
            <span className="text-slate-400 block mb-1 flex items-center gap-1.5">
              <Globe className="w-3.5 h-3.5 text-slate-500" />
              Source IP
            </span>
            <span className="font-mono font-bold text-slate-200">{srcEvent.source_ip || "N/A"}</span>
          </div>

          <div className="bg-[#0B1329] p-3 rounded-lg border border-[#1F2937]">
            <span className="text-slate-400 block mb-1 flex items-center gap-1.5">
              <Globe className="w-3.5 h-3.5 text-slate-500" />
              Destination IP
            </span>
            <span className="font-mono font-bold text-slate-200">{srcEvent.destination_ip || "N/A"}</span>
          </div>

          <div className="bg-[#0B1329] p-3 rounded-lg border border-[#1F2937]">
            <span className="text-slate-400 block mb-1 flex items-center gap-1.5">
              <User className="w-3.5 h-3.5 text-slate-500" />
              Username / User
            </span>
            <span className="font-bold text-purple-300">{srcEvent.username || "N/A"}</span>
          </div>

          <div className="bg-[#0B1329] p-3 rounded-lg border border-[#1F2937]">
            <span className="text-slate-400 block mb-1">Event Type</span>
            <span className="font-bold text-slate-200">{srcEvent.event_type || predicted_threat_type}</span>
          </div>

          <div className="bg-[#0B1329] p-3 rounded-lg border border-[#1F2937]">
            <span className="text-slate-400 block mb-1 flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5 text-slate-500" />
              Event Timestamp
            </span>
            <span className="font-mono text-slate-300">{eventTsFormatted}</span>
          </div>

          <div className="bg-[#0B1329] p-3 rounded-lg border border-[#1F2937]">
            <span className="text-slate-400 block mb-1">Device / Asset</span>
            <span className="font-semibold text-slate-200">{srcEvent.device_name || srcEvent.asset_name || "N/A"}</span>
          </div>

          <div className="bg-[#0B1329] p-3 rounded-lg border border-[#1F2937]">
            <span className="text-slate-400 block mb-1">Severity & CVSS</span>
            <div className="flex items-center gap-2">
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${SEVERITY_BADGE[srcEvent.severity] || "bg-slate-500/20 text-slate-300 border-slate-500/30"}`}>
                {srcEvent.severity || "N/A"}
              </span>
              <span className="font-mono text-slate-300">CVSS: {srcEvent.cvss_score != null ? srcEvent.cvss_score : "N/A"}</span>
            </div>
          </div>

          <div className="bg-[#0B1329] p-3 rounded-lg border border-[#1F2937]">
            <span className="text-slate-400 block mb-1">Protocol & Status</span>
            <div className="flex items-center gap-2 font-mono">
              <span className="bg-slate-800 text-slate-300 px-1.5 py-0.5 rounded text-[11px] font-bold">{srcEvent.protocol || "N/A"}</span>
              <span className="text-emerald-400 font-bold">{srcEvent.event_status || "N/A"}</span>
            </div>
          </div>
        </div>
      </div>

      {/* SECTION B: AI Analysis & Multi-Layer Model Signals */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Confidence Card (Col Span 1) */}
        <div className="lg:col-span-1">
          <ConfidenceCard
            confidenceScore={confidence_score}
            verdict={verdict}
            predictedThreatType={predicted_threat_type}
            anomalyLabel={anomaly_label}
            rfTopProbability={rf_top_probability}
            rfConfidenceNote={rf_confidence_note}
          />
        </div>

        {/* Model Signals Breakdown (Col Span 2) */}
        <div className="lg:col-span-2 bg-[#111827] border border-[#1F2937] rounded-xl p-5 shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between border-b border-[#1F2937] pb-3 mb-4">
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Activity className="w-4 h-4 text-blue-400" />
              <span>Section B: Multi-Layer Model Signals</span>
            </h3>
            <span className="text-xs font-mono text-slate-400 bg-[#0B1329] px-2 py-0.5 rounded border border-[#1F2937]">
              Layer 1 + Layer 2 + Rules
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {/* Layer 1: Isolation Forest */}
            <div className="bg-[#0B1329] p-3.5 rounded-lg border border-[#1F2937] space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-300">Layer 1: IF Anomaly</span>
                <Cpu className="w-3.5 h-3.5 text-blue-400" />
              </div>
              <div className="space-y-1">
                <div className="flex justify-between text-xs">
                  <span className="text-slate-400">Norm Score:</span>
                  <span className="font-mono font-bold text-slate-200">
                    {model_signals.if_anomaly_normalized ?? anomaly_score.toFixed(1)}%
                  </span>
                </div>
                <div className="flex justify-between text-xs">
                  <span className="text-slate-400">Raw Score:</span>
                  <span className="font-mono text-slate-300 text-[11px]">
                    {anomaly_score_raw.toFixed(5)}
                  </span>
                </div>
                <div className="flex justify-between text-xs pt-1 border-t border-[#1F2937]">
                  <span className="text-slate-400">Label:</span>
                  <span className={`font-bold ${anomaly_label === "Suspicious" ? "text-amber-400" : "text-emerald-400"}`}>
                    {anomaly_label}
                  </span>
                </div>
              </div>
            </div>

            {/* Layer 2: Random Forest */}
            <div className="bg-[#0B1329] p-3.5 rounded-lg border border-[#1F2937] space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-300">Layer 2: RF Threat</span>
                <Layers className="w-3.5 h-3.5 text-purple-400" />
              </div>
              <div className="space-y-1">
                <div className="flex justify-between text-xs">
                  <span className="text-slate-400">Top Class:</span>
                  <span className="font-bold text-purple-300 truncate max-w-[100px]" title={predicted_threat_type}>
                    {predicted_threat_type}
                  </span>
                </div>
                <div className="flex justify-between text-xs">
                  <span className="text-slate-400">Probability:</span>
                  <span className="font-mono text-slate-300">
                    {(rf_top_probability * 100).toFixed(1)}%
                  </span>
                </div>
                <div className="flex justify-between text-xs pt-1 border-t border-[#1F2937]">
                  <span className="text-slate-400">Signal Note:</span>
                  <span className="font-bold text-blue-300 uppercase text-[10px]">
                    {rf_confidence_note}
                  </span>
                </div>
              </div>
            </div>

            {/* Layer 3: Rule Engine */}
            <div className="bg-[#0B1329] p-3.5 rounded-lg border border-[#1F2937] space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-300">Layer 3: Rules</span>
                <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
              </div>
              <div className="space-y-1">
                <div className="flex justify-between text-xs">
                  <span className="text-slate-400">Rule Score:</span>
                  <span className="font-mono font-bold text-slate-200">
                    {rule_score.toFixed(1)} / 100
                  </span>
                </div>
                <div className="flex justify-between text-xs">
                  <span className="text-slate-400">Rules Fired:</span>
                  <span className="font-mono text-slate-300">
                    {triggered_rules.length}
                  </span>
                </div>
                <div className="flex justify-between text-xs pt-1 border-t border-[#1F2937]">
                  <span className="text-slate-400">Weight:</span>
                  <span className="font-bold text-amber-300">
                    40% Weight
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Explainable AI Reasons Section */}
      <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex items-center justify-between border-b border-[#1F2937] pb-3">
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <FileText className="w-4 h-4 text-emerald-400" />
            <span>Explainable AI — Evidentiary Reasons</span>
          </h3>
          <span className="text-xs font-mono text-slate-400">
            {reasons.length} evidence factor(s)
          </span>
        </div>

        {reasons.length === 0 ? (
          <div className="p-6 text-center text-xs text-slate-500 bg-[#0B1329] rounded-lg border border-[#1F2937]">
            No rule or anomaly explanation triggers for this event. Event exhibits standard baseline behavior.
          </div>
        ) : (
          <div className="space-y-2.5">
            {reasons.map((r, idx) => {
              const badgeStyle = SEVERITY_BADGE[r.severity] || SEVERITY_BADGE.Low;
              const isIfSignal = r.rule_id === "IF_ANOMALY_SIGNAL";

              return (
                <div
                  key={idx}
                  className="bg-[#0B1329] border border-[#1F2937] rounded-lg p-3.5 flex flex-col md:flex-row md:items-center justify-between gap-3 hover:border-slate-700 transition-colors"
                >
                  <div className="flex items-start gap-3">
                    <div className="mt-0.5">
                      {isIfSignal ? (
                        <AlertTriangle className="w-4 h-4 text-amber-400" />
                      ) : (
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      )}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-blue-400">
                          {r.rule_id}
                        </span>
                        <span className={`px-2 py-0.2 rounded text-[10px] font-bold border ${badgeStyle}`}>
                          {r.severity}
                        </span>
                      </div>
                      <p className="text-xs font-medium text-slate-200 mt-1">
                        {r.reason}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 self-end md:self-auto shrink-0">
                    <span className="text-xs font-mono text-slate-400">
                      Points:
                    </span>
                    <span className="px-2 py-0.5 rounded font-mono text-xs font-bold bg-[#111827] text-slate-200 border border-[#1F2937]">
                      +{r.points}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Model Metadata Section */}
      {model_metadata && Object.keys(model_metadata).length > 0 && (
        <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 shadow-sm text-xs space-y-2">
          <span className="font-bold text-slate-300 uppercase tracking-wider text-[11px] block">
            Model & Pipeline Version Metadata
          </span>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-[11px] text-slate-400">
            <div>
              <span className="text-slate-500 block">Preprocessor:</span>
              <span className="text-slate-200 font-bold">{model_metadata.preprocessor_version || "N/A"}</span>
            </div>
            <div>
              <span className="text-slate-500 block">Isolation Forest:</span>
              <span className="text-slate-200 font-bold">{model_metadata.if_model_version || "N/A"}</span>
            </div>
            <div>
              <span className="text-slate-500 block">Random Forest:</span>
              <span className="text-slate-200 font-bold">{model_metadata.clf_model_version || "N/A"}</span>
            </div>
            <div>
              <span className="text-slate-500 block">Scoring Engine:</span>
              <span className="text-slate-200 font-bold">{model_metadata.scoring_design_version || "N/A"}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
