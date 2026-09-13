import { ShieldAlert, AlertTriangle, ShieldCheck, Cpu, Info } from "lucide-react";

const VERDICT_THEME = {
  Normal: {
    bg: "bg-emerald-500/10 border-emerald-500/20 text-emerald-400",
    badge: "bg-emerald-500/20 text-emerald-300 border-emerald-500/30",
    bar: "bg-emerald-500",
    Icon: ShieldCheck,
  },
  Suspicious: {
    bg: "bg-amber-500/10 border-amber-500/20 text-amber-400",
    badge: "bg-amber-500/20 text-amber-300 border-amber-500/30",
    bar: "bg-amber-500",
    Icon: AlertTriangle,
  },
  Critical: {
    bg: "bg-red-500/10 border-red-500/20 text-red-400",
    badge: "bg-red-500/20 text-red-300 border-red-500/30",
    bar: "bg-red-500",
    Icon: ShieldAlert,
  },
};

const RF_NOTE_THEME = {
  low: "bg-slate-800 text-slate-400 border-slate-700",
  moderate: "bg-blue-500/15 text-blue-300 border-blue-500/30",
  high: "bg-purple-500/15 text-purple-300 border-purple-500/30",
};

export default function ConfidenceCard({
  confidenceScore = 0,
  verdict = "Normal",
  predictedThreatType = "Unknown",
  anomalyLabel = "Normal",
  rfTopProbability = 0,
  rfConfidenceNote = "low",
}) {
  const theme = VERDICT_THEME[verdict] || VERDICT_THEME.Normal;
  const { Icon, bg, badge, bar } = theme;

  const rfNoteStyle = RF_NOTE_THEME[rfConfidenceNote] || RF_NOTE_THEME.low;
  const rfProbPct = (rfTopProbability * 100).toFixed(1);

  return (
    <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-5 shadow-sm flex flex-col justify-between hover:border-slate-700 transition-all duration-200 select-none">
      {/* Top Header */}
      <div className="flex items-start justify-between gap-3 mb-4">
        <div>
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            Hybrid Threat Confidence
          </span>
          <h4 className="text-lg font-bold text-slate-100 tracking-tight mt-0.5">
            {predictedThreatType}
          </h4>
        </div>
        <div className={`flex items-center gap-1.5 px-3 py-1 rounded-lg border text-xs font-bold ${badge}`}>
          <Icon className="w-4 h-4" />
          <span>{verdict}</span>
        </div>
      </div>

      {/* Main Score Bar */}
      <div className="space-y-2 mb-4">
        <div className="flex items-baseline justify-between">
          <span className="text-3xl font-extrabold text-slate-100 font-mono tracking-tight">
            {confidenceScore.toFixed(1)}%
          </span>
          <span className="text-xs text-slate-400 font-medium">
            50% IF + 40% Rules + 10% RF
          </span>
        </div>
        <div className="w-full h-2.5 bg-[#1E293B] rounded-full overflow-hidden p-0.5 border border-[#1F2937]">
          <div
            className={`h-full rounded-full transition-all duration-500 ${bar}`}
            style={{ width: `${Math.min(100, Math.max(0, confidenceScore))}%` }}
          />
        </div>
      </div>

      {/* Signals Summary Footer */}
      <div className="pt-3 border-t border-[#1F2937] grid grid-cols-2 gap-2 text-xs">
        {/* Isolation Forest Signal */}
        <div className="flex flex-col gap-0.5 bg-[#0B1329] p-2.5 rounded-lg border border-[#1F2937]">
          <span className="text-[11px] text-slate-400 flex items-center gap-1 font-medium">
            <Cpu className="w-3 h-3 text-blue-400" />
            <span>IF Anomaly</span>
          </span>
          <span className={`text-xs font-bold ${anomalyLabel === "Suspicious" ? "text-amber-400" : "text-emerald-400"}`}>
            {anomalyLabel}
          </span>
        </div>

        {/* Random Forest Class Probability Signal */}
        <div className="flex flex-col gap-0.5 bg-[#0B1329] p-2.5 rounded-lg border border-[#1F2937]">
          <span className="text-[11px] text-slate-400 flex items-center gap-1 font-medium" title="RF top class probability soft signal">
            <Info className="w-3 h-3 text-purple-400" />
            <span>RF Soft Signal</span>
          </span>
          <div className="flex items-center justify-between">
            <span className="font-mono text-xs font-bold text-slate-200">
              {rfProbPct}%
            </span>
            <span className={`px-1.5 py-0.2 rounded text-[10px] font-semibold border ${rfNoteStyle}`}>
              {rfConfidenceNote}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
