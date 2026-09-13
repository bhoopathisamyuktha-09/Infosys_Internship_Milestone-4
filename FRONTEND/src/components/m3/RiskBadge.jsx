import React from "react";
import { useTheme } from "../../context/ThemeContext";

// ─── Dark-mode class sets (unchanged from original) ──────────────────────────
const RISK_LEVEL_DARK = {
  Critical: "bg-red-500/20 text-red-300 border-red-500/40",
  High:     "bg-orange-500/20 text-orange-300 border-orange-500/40",
  Moderate: "bg-amber-500/20 text-amber-300 border-amber-500/40",
  Medium:   "bg-blue-500/20 text-blue-300 border-blue-500/40",
  Low:      "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
};

const PRIORITY_DARK = {
  CRITICAL_IMMEDIATE: "bg-red-600/25 text-red-200 border-red-500/50 font-bold",
  HIGH_IMMEDIATE:     "bg-orange-600/25 text-orange-200 border-orange-500/50 font-bold",
  HIGH:               "bg-orange-500/20 text-orange-300 border-orange-500/40",
  MEDIUM:             "bg-blue-500/20 text-blue-300 border-blue-500/40",
  LOW:                "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
};

const STATUS_DARK = {
  Open:             "bg-red-500/15 text-red-300 border-red-500/30",
  Investigating:    "bg-amber-500/15 text-amber-300 border-amber-500/30",
  Resolved:         "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  "False Positive": "bg-slate-500/15 text-slate-300 border-slate-500/30",
};

// ─── Light-mode class sets (WCAG-readable, semantic colours preserved) ────────
const RISK_LEVEL_LIGHT = {
  Critical: "bg-red-100 text-red-800 border-red-300",
  High:     "bg-orange-100 text-orange-800 border-orange-300",
  Moderate: "bg-amber-100 text-amber-800 border-amber-300",
  Medium:   "bg-blue-100 text-blue-800 border-blue-300",
  Low:      "bg-emerald-100 text-emerald-800 border-emerald-300",
};

const PRIORITY_LIGHT = {
  CRITICAL_IMMEDIATE: "bg-red-600 text-white border-red-700 font-bold",
  HIGH_IMMEDIATE:     "bg-orange-500 text-white border-orange-600 font-bold",
  HIGH:               "bg-orange-100 text-orange-800 border-orange-300",
  MEDIUM:             "bg-blue-100 text-blue-800 border-blue-300",
  LOW:                "bg-emerald-100 text-emerald-800 border-emerald-300",
};

const STATUS_LIGHT = {
  Open:             "bg-red-100 text-red-800 border-red-300",
  Investigating:    "bg-amber-100 text-amber-800 border-amber-300",
  Resolved:         "bg-emerald-100 text-emerald-800 border-emerald-300",
  "False Positive": "bg-slate-100 text-slate-700 border-slate-300",
};

// ─── Shared fallbacks ─────────────────────────────────────────────────────────
const DARK_FALLBACK  = "bg-slate-500/20 text-slate-300 border-slate-500/30";
const LIGHT_FALLBACK = "bg-slate-100 text-slate-700 border-slate-300";

// ─── Components ──────────────────────────────────────────────────────────────
export function RiskLevelBadge({ level, size = "sm" }) {
  const { isDark } = useTheme();
  const style = isDark
    ? (RISK_LEVEL_DARK[level] || DARK_FALLBACK)
    : (RISK_LEVEL_LIGHT[level] || LIGHT_FALLBACK);
  const sizeClass = size === "lg" ? "px-3 py-1 text-xs" : "px-2 py-0.5 text-[11px]";
  return (
    <span className={`inline-flex items-center gap-1 rounded-md border font-semibold tracking-wide ${style} ${sizeClass}`}>
      <span className="h-1.5 w-1.5 rounded-full bg-current opacity-80" />
      <span>{level || "Unknown"}</span>
    </span>
  );
}

export function PriorityBadge({ priority, size = "sm" }) {
  const { isDark } = useTheme();
  const style = isDark
    ? (PRIORITY_DARK[priority] || DARK_FALLBACK)
    : (PRIORITY_LIGHT[priority] || LIGHT_FALLBACK);
  const sizeClass = size === "lg" ? "px-3 py-1 text-xs" : "px-2 py-0.5 text-[11px]";
  const formatted = priority ? priority.replace("_", " ") : "UNKNOWN";
  return (
    <span className={`inline-flex items-center gap-1 rounded-md border font-mono font-semibold tracking-wider ${style} ${sizeClass}`}>
      {formatted}
    </span>
  );
}

export function StatusBadge({ status, size = "sm" }) {
  const { isDark } = useTheme();
  const style = isDark
    ? (STATUS_DARK[status] || DARK_FALLBACK)
    : (STATUS_LIGHT[status] || LIGHT_FALLBACK);
  const sizeClass = size === "lg" ? "px-3 py-1 text-xs" : "px-2 py-0.5 text-[11px]";
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md border font-medium ${style} ${sizeClass}`}>
      <span className="h-1.5 w-1.5 rounded-full bg-current opacity-80" />
      <span>{status || "Open"}</span>
    </span>
  );
}

export function RiskScoreBadge({ score, level, size = "md" }) {
  const { isDark } = useTheme();
  const style = isDark
    ? (RISK_LEVEL_DARK[level] || DARK_FALLBACK)
    : (RISK_LEVEL_LIGHT[level] || LIGHT_FALLBACK);
  const isLarge = size === "lg";
  return (
    <div className={`inline-flex items-center justify-center font-bold font-mono rounded-lg border ${style} ${isLarge ? "h-12 w-14 text-xl" : "h-7 w-9 text-xs"}`}>
      {score ?? "--"}
    </div>
  );
}

// ─── Legacy exports (kept for backwards compatibility with global.css overrides)
export const RISK_LEVEL_STYLES = RISK_LEVEL_DARK;
export const PRIORITY_STYLES   = PRIORITY_DARK;
export const STATUS_STYLES     = STATUS_DARK;
