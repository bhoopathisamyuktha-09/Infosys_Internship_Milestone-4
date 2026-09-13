import { AlertTriangle, Zap, Lock, Activity, ShieldAlert } from "lucide-react";

const ICON_MAP = {
  activity: { Icon: Activity, box: "bg-blue-500/10 border-blue-500/20 text-blue-400" },
  critical: { Icon: ShieldAlert, box: "bg-red-500/10 border-red-500/20 text-red-400" },
  lightning: { Icon: Zap, box: "bg-amber-500/10 border-amber-500/20 text-amber-400" },
  lock: { Icon: Lock, box: "bg-slate-800/80 border-slate-700 text-slate-300" },
  alert: { Icon: AlertTriangle, box: "bg-red-500/10 border-red-500/20 text-red-400" },
};

const STATUS_DOT = {
  critical: "bg-red-500 text-red-400",
  elevated: "bg-red-500 text-red-400",
  moderate: "bg-amber-500 text-amber-400",
  normal: "bg-emerald-500 text-emerald-400",
};

export default function KpiCard({ title, value, statusText, statusType = "normal", iconType = "activity" }) {
  const { Icon, box } = ICON_MAP[iconType] || ICON_MAP.activity;
  const dot = STATUS_DOT[statusType] || STATUS_DOT.normal;
  const [dotBg, textColor] = dot.split(" ");

  return (
    <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 shadow-sm flex flex-col justify-between hover:border-slate-700 hover:-translate-y-0.5 transition-all duration-200 select-none">
      <div className="flex items-start justify-between gap-2 mb-2">
        <span className="text-xs font-semibold text-slate-400 tracking-tight">
          {title}
        </span>
        <div className={`w-8 h-8 rounded-lg border flex items-center justify-center shrink-0 ${box}`}>
          <Icon className="w-4 h-4" />
        </div>
      </div>

      <span className="text-2xl md:text-3xl font-extrabold text-slate-100 tracking-tight font-mono">
        {value}
      </span>

      <div className="pt-2.5 mt-2.5 border-t border-[#1F2937] flex items-center">
        <div className={`flex items-center gap-1.5 text-xs font-semibold ${textColor}`}>
          <span className={`w-2 h-2 rounded-full ${dotBg}`}></span>
          <span>{statusText}</span>
        </div>
      </div>
    </div>
  );
}
