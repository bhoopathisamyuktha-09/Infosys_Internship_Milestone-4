import React, { useState, useEffect, useRef } from "react";
import { Link } from "react-router-dom";
import {
  FiGitCommit,
  FiClock,
  FiShield,
  FiPlay,
  FiRotateCcw,
  FiPause,
  FiEye,
  FiEyeOff,
  FiActivity,
  FiArrowRight,
} from "react-icons/fi";

const STAGE_TACTIC_COLORS = {
  "Initial Access": "border-blue-500/40 bg-blue-500/10 text-blue-300",
  "Credential Access": "border-amber-500/40 bg-amber-500/10 text-amber-300",
  "Privilege Escalation": "border-purple-500/40 bg-purple-500/10 text-purple-300",
  Discovery: "border-cyan-500/40 bg-cyan-500/10 text-cyan-300",
  Execution: "border-red-500/40 bg-red-500/10 text-red-300",
  Exfiltration: "border-orange-500/40 bg-orange-500/10 text-orange-300",
  "Defense Evasion": "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
};

export default function AttackChainTimeline({ attackChain }) {
  const stages = attackChain?.stages || [];
  const stagesCount = stages.length;

  // Check if OS prefers reduced motion
  const prefersReducedMotion =
    typeof window !== "undefined" &&
    window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const [animationEnabled, setAnimationEnabled] = useState(!prefersReducedMotion);
  const [revealedCount, setRevealedCount] = useState(prefersReducedMotion ? stagesCount : 1);
  const [activeStageIdx, setActiveStageIdx] = useState(prefersReducedMotion ? -1 : 0);
  const [isPlaying, setIsPlaying] = useState(!prefersReducedMotion);

  const timerRef = useRef(null);

  // Sequential progression effect
  useEffect(() => {
    if (!animationEnabled || !isPlaying || stagesCount <= 1) {
      setRevealedCount(stagesCount);
      setActiveStageIdx(-1);
      return;
    }

    // Step through each stage sequentially
    timerRef.current = setInterval(() => {
      setRevealedCount((prev) => {
        if (prev < stagesCount) {
          setActiveStageIdx(prev);
          return prev + 1;
        } else {
          clearInterval(timerRef.current);
          setIsPlaying(false);
          setActiveStageIdx(-1);
          return stagesCount;
        }
      });
    }, 380);

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [animationEnabled, isPlaying, stagesCount]);

  function handleReplay() {
    if (timerRef.current) clearInterval(timerRef.current);
    setRevealedCount(1);
    setActiveStageIdx(0);
    setIsPlaying(true);
    setAnimationEnabled(true);
  }

  function toggleAnimation() {
    if (animationEnabled) {
      if (timerRef.current) clearInterval(timerRef.current);
      setAnimationEnabled(false);
      setIsPlaying(false);
      setRevealedCount(stagesCount);
      setActiveStageIdx(-1);
    } else {
      setAnimationEnabled(true);
      handleReplay();
    }
  }

  if (!attackChain || !attackChain.attack_chain_detected || !stagesCount) {
    return (
      <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-6 text-center space-y-2">
        <div className="flex justify-center">
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-slate-800 text-slate-400">
            <FiGitCommit className="text-xl" />
          </div>
        </div>
        <h4 className="text-sm font-semibold text-slate-300">No Multi-Stage Attack Chain Detected</h4>
        <p className="text-xs text-slate-400 max-w-md mx-auto">
          Correlated events do not match known canonical multi-stage progression patterns (Brute Force, Privilege Escalation, or Data Exfiltration).
        </p>
      </div>
    );
  }

  const { attack_chain_id, attack_chain_type, confidence, description } = attackChain;

  return (
    <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-5 md:p-6 space-y-5">
      {/* Header with Animation Controls */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-[#1F2937] pb-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-purple-500/20 text-purple-400 text-xs shrink-0">
              <FiGitCommit />
            </span>
            <h3 className="text-base font-bold text-slate-100">{attack_chain_type}</h3>
            {attack_chain_id && (
              <span className="font-mono text-[11px] font-semibold px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-[#1F2937]">
                {attack_chain_id}
              </span>
            )}
            <span className="text-[11px] font-semibold px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
              {stagesCount} Stages Detected
            </span>
            {confidence && (
              <span className="text-[11px] font-semibold px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30">
                Confidence: {confidence}
              </span>
            )}
          </div>
          <p className="text-xs text-slate-400">{description}</p>
        </div>

        {/* Animation Action Controls */}
        <div className="flex items-center gap-2 self-end sm:self-auto shrink-0">
          <button
            type="button"
            onClick={toggleAnimation}
            className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-[11px] font-semibold border transition-colors cursor-pointer ${
              animationEnabled
                ? "bg-blue-500/15 text-blue-300 border-blue-500/40 hover:bg-blue-500/25"
                : "bg-[#1E293B] text-slate-400 border-[#334155] hover:text-slate-200"
            }`}
            title={animationEnabled ? "Disable sequential animation" : "Enable sequential animation"}
          >
            {animationEnabled ? <FiEye className="text-xs" /> : <FiEyeOff className="text-xs" />}
            <span>{animationEnabled ? "Animated" : "Static"}</span>
          </button>

          {animationEnabled && (
            <button
              type="button"
              onClick={handleReplay}
              disabled={isPlaying}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-[11px] font-semibold bg-[#1E293B] hover:bg-slate-700 text-slate-300 border border-[#334155] transition-colors disabled:opacity-40 cursor-pointer"
              title="Replay chronological attack progression"
            >
              <FiRotateCcw className={`text-xs ${isPlaying ? "animate-spin" : ""}`} />
              <span>{isPlaying ? "Simulating..." : "Replay Progression"}</span>
            </button>
          )}
        </div>
      </div>

      {/* Chronological Attack Chain Timeline Stepper */}
      <div className="relative pl-6 sm:pl-8 space-y-6 before:absolute before:left-3 sm:before:left-4 before:top-3 before:bottom-3 before:w-0.5 before:bg-[#1F2937]">
        {stages.map((stage, idx) => {
          const tacticClass =
            STAGE_TACTIC_COLORS[stage.tactic] || "border-slate-500/40 bg-slate-500/10 text-slate-300";
          const isRevealed = !animationEnabled || idx < revealedCount;
          const isActive = animationEnabled && idx === activeStageIdx;

          return (
            <div
              key={stage.event_id || idx}
              className={`relative group transition-all duration-300 ${
                isRevealed ? "opacity-100 translate-y-0" : "opacity-25 translate-y-1 pointer-events-none"
              }`}
            >
              {/* Stepper Node Icon with pulsing animation on active step */}
              <div
                className={`absolute -left-6 sm:-left-8 top-1 flex h-6 w-6 items-center justify-center rounded-full text-[10px] font-bold shadow-md transition-all duration-300 ${
                  isActive
                    ? "bg-blue-600 border-2 border-blue-400 text-white ring-4 ring-blue-500/40 scale-110"
                    : isRevealed
                    ? "bg-[#111827] border-2 border-blue-500 text-blue-400"
                    : "bg-[#111827] border border-slate-700 text-slate-500"
                }`}
              >
                {stage.stage_order}
              </div>

              {/* Stage Card */}
              <div
                className={`bg-[#1E293B] border rounded-lg p-4 space-y-2.5 transition-all duration-300 ${
                  isActive
                    ? "border-blue-500/80 shadow-lg shadow-blue-900/20 bg-[#1E293B]/95 ring-1 ring-blue-500/30"
                    : isRevealed
                    ? "border-[#1F2937] hover:border-slate-600"
                    : "border-[#1F2937]/50"
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-bold text-slate-100">{stage.stage_name}</span>
                    <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border ${tacticClass}`}>
                      {stage.tactic || "Adversary Tactic"}
                    </span>
                    {isActive && (
                      <span className="flex items-center gap-1 text-[10px] font-mono font-bold text-blue-400 animate-pulse">
                        <span className="w-1.5 h-1.5 rounded-full bg-blue-400"></span>
                        <span>ANALYZING STAGE</span>
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-1.5 text-[11px] text-slate-400 font-mono">
                    <FiClock className="text-xs" />
                    <span>{stage.timestamp}</span>
                  </div>
                </div>

                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs pt-1 border-t border-[#1F2937]/80">
                  <div className="flex items-center gap-3">
                    <span className="text-slate-400 flex items-center gap-1">
                      <span>Event:</span>
                      <Link
                        to={`/dashboard/events/${stage.event_id}`}
                        title={`Inspect atomic security event ${stage.event_id}`}
                        className="font-mono font-bold text-blue-400 hover:text-blue-300 hover:underline flex items-center gap-0.5"
                      >
                        <span>{stage.event_id}</span>
                        <FiArrowRight className="text-[10px]" />
                      </Link>
                    </span>
                    <span className="text-slate-400">
                      Type: <span className="font-semibold text-slate-200">{stage.event_type}</span>
                    </span>
                  </div>

                  {stage.technique_id && (
                    <div className="flex items-center gap-1 text-[11px] text-purple-300 font-mono">
                      <FiShield className="text-xs text-purple-400" />
                      <span>{stage.technique_id}</span>
                      {stage.technique_name && (
                        <span className="text-slate-400 truncate max-w-[200px]">({stage.technique_name})</span>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
