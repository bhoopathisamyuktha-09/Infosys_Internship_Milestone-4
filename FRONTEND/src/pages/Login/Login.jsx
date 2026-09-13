import { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  FaShieldAlt,
  FaUser,
  FaLock,
  FaEye,
  FaEyeSlash,
  FaCheckCircle,
} from "react-icons/fa";

function Login() {
  const navigate = useNavigate();

  const [showPassword, setShowPassword] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [formError, setFormError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  // NOTE: No real authentication is implemented here.
  // Authentication (JWT / session tokens / backend verification) is explicitly
  // out of scope. This form validates that fields are not empty before granting access.
  const handleLogin = (e) => {
    e.preventDefault();
    setFormError("");

    if (!email.trim()) {
      setFormError("Email address is required.");
      return;
    }
    if (!password.trim()) {
      setFormError("Password is required.");
      return;
    }

    // Brief polished transition before navigation (200ms — perceptible but not sluggish)
    setSubmitting(true);
    setTimeout(() => navigate("/dashboard"), 220);
  };

  return (
    <div className="login-screen relative min-h-screen overflow-y-auto bg-slate-950 flex flex-col justify-center py-6 sm:py-8 lg:py-0">

      {/* ======================== ANIMATION STYLES ======================== */}
      <style>{`
        /* ── Keyframes ── */
        @keyframes lgnFadeUp {
          from { opacity: 0; transform: translateY(18px); }
          to   { opacity: 1; transform: translateY(0);    }
        }

        @keyframes lgnFadeIn {
          from { opacity: 0; }
          to   { opacity: 1; }
        }

        @keyframes shieldOneGlow {
          0%   { box-shadow: 0 0 0px rgba(37,99,235,0);     }
          55%  { box-shadow: 0 0 28px rgba(59,130,246,0.85); }
          100% { box-shadow: 0 0 14px rgba(37,99,235,0.35);  }
        }

        @keyframes lgnSubmitPulse {
          0%   { box-shadow: 0 4px 15px rgba(37,99,235,0.25); }
          50%  { box-shadow: 0 4px 28px rgba(37,99,235,0.55); }
          100% { box-shadow: 0 4px 15px rgba(37,99,235,0.25); }
        }

        /* ── Panel: logo fades in immediately ── */
        .lgn-logo {
          opacity: 0;
          animation: lgnFadeUp 0.55s cubic-bezier(0.16,1,0.3,1) 0.05s forwards;
        }

        /* ── Panel: heading appears right after logo ── */
        .lgn-heading {
          opacity: 0;
          animation: lgnFadeUp 0.55s cubic-bezier(0.16,1,0.3,1) 0.20s forwards;
        }

        /* ── Panel: description follows ── */
        .lgn-desc {
          opacity: 0;
          animation: lgnFadeIn 0.50s ease-out 0.40s forwards;
        }

        /* ── Panel: badge ── */
        .lgn-badge {
          opacity: 0;
          animation: lgnFadeIn 0.45s ease-out 0.55s forwards;
        }

        /* ── Panel: feature items staggered ── */
        .lgn-feat-1 { opacity:0; animation: lgnFadeUp 0.40s ease-out 0.65s forwards; }
        .lgn-feat-2 { opacity:0; animation: lgnFadeUp 0.40s ease-out 0.78s forwards; }
        .lgn-feat-3 { opacity:0; animation: lgnFadeUp 0.40s ease-out 0.91s forwards; }
        .lgn-feat-4 { opacity:0; animation: lgnFadeUp 0.40s ease-out 1.04s forwards; }

        /* ── Card: fades up with a slight delay ── */
        .lgn-card {
          opacity: 0;
          animation: lgnFadeUp 0.70s cubic-bezier(0.16,1,0.3,1) 0.30s forwards;
        }

        /* ── Shield logo: single glow burst ── */
        .lgn-shield-glow {
          animation: shieldOneGlow 0.90s ease-out 0.45s forwards;
        }

        /* ── Login button: subtle continuous shadow to invite interaction ── */
        .lgn-btn:not(:disabled) {
          animation: lgnSubmitPulse 2.8s ease-in-out 1.2s infinite;
        }

        /* ── Submitting state ── */
        .lgn-btn.lgn-submitting {
          animation: none !important;
          opacity: 0.80;
        }

        /* ── Reduced-motion: instant reveal, no glow, no pulse ── */
        @media (prefers-reduced-motion: reduce) {
          .lgn-logo, .lgn-heading, .lgn-desc, .lgn-badge,
          .lgn-feat-1, .lgn-feat-2, .lgn-feat-3, .lgn-feat-4,
          .lgn-card, .lgn-shield-glow, .lgn-btn {
            animation: none !important;
            opacity: 1 !important;
            transform: none !important;
            box-shadow: none !important;
          }
        }

        /* ── Absolute contrast isolation against html.light ── */
        html.light .login-screen .text-slate-100,
        .login-screen .text-slate-100,
        html.light .login-screen .text-slate-200,
        .login-screen .text-slate-200 {
          color: #E2E8F0 !important;
        }
        html.light .login-screen .text-slate-300,
        .login-screen .text-slate-300 {
          color: #CBD5E1 !important;
        }
        html.light .login-screen .text-slate-400,
        .login-screen .text-slate-400,
        html.light .login-screen .text-slate-500,
        .login-screen .text-slate-500 {
          color: #94A3B8 !important;
        }
        html.light .login-screen input:not([type="checkbox"]):not([type="radio"]),
        .login-screen input:not([type="checkbox"]):not([type="radio"]) {
          background-color: #020617 !important;
          border-color: #334155 !important;
          color: #FFFFFF !important;
        }
        html.light .login-screen input::placeholder,
        .login-screen input::placeholder {
          color: #94A3B8 !important;
        }
      `}</style>

      {/* ====================== BACKGROUND AMBIANCE ====================== */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden">
        {/* Blue top-left glow */}
        <div className="absolute -top-40 -left-40 h-[520px] w-[520px] rounded-full bg-blue-600/15 blur-[160px]" />
        {/* Cyan bottom-right glow */}
        <div className="absolute -bottom-40 -right-40 h-[520px] w-[520px] rounded-full bg-cyan-500/15 blur-[160px]" />
        {/* Subtle grid lines — enterprise SOC texture */}
        <div
          className="absolute inset-0 opacity-[0.025]"
          style={{
            backgroundImage:
              "linear-gradient(rgba(148,163,184,1) 1px, transparent 1px), linear-gradient(90deg, rgba(148,163,184,1) 1px, transparent 1px)",
            backgroundSize: "40px 40px",
          }}
        />
      </div>

      {/* ========================= MAIN CONTAINER ======================== */}
      <div className="relative z-10 flex w-full h-full items-center justify-center px-4 sm:px-8 py-4 lg:py-6">
        <div className="flex w-full max-w-6xl flex-col lg:flex-row items-center justify-center lg:justify-between gap-8 lg:gap-12 xl:gap-16">

          {/* ============================================================ */}
          {/* LEFT INFORMATION PANEL                                        */}
          {/* ============================================================ */}
          <div className="flex flex-1 flex-col text-center lg:text-left items-center lg:items-start max-w-lg lg:max-w-none">

            {/* Logo + Brand */}
            <div className="flex items-center gap-4 lgn-logo justify-center lg:justify-start">
              <div className="rounded-2xl bg-blue-600 p-3.5 sm:p-4 shadow-2xl lgn-shield-glow shrink-0">
                <FaShieldAlt className="text-3xl sm:text-4xl text-white" />
              </div>
              <div>
                <h1 className="text-3xl xl:text-4xl font-extrabold text-white tracking-tight">
                  SentinelAI
                </h1>
                <p className="mt-1 text-sm xl:text-base font-semibold text-blue-300">
                  Creation of Security Operations Dashboard for Threat Detection with Risk Mitigation Analytics
                </p>
              </div>
            </div>

            {/* Description */}
            <p className="lgn-desc mt-6 max-w-lg text-sm xl:text-base leading-relaxed text-slate-300">
              Continuous security telemetry monitoring, AI-assisted threat detection,
              explainable enterprise risk scoring, and strategic mitigation analytics
              through a unified Security Operations Center platform.
            </p>

            {/* Feature Badge */}
            <div className="lgn-badge mt-5 inline-flex w-fit rounded-full border border-blue-500/30 bg-blue-500/10 px-4 py-1.5">
              <span className="text-xs font-semibold tracking-wide text-blue-300 uppercase font-mono">
                Enterprise SOC Platform
              </span>
            </div>

            {/* Staggered Feature List */}
            <div className="mt-6 space-y-3.5 text-left w-full max-w-md lg:max-w-none">
              <div className="flex items-center gap-3 lgn-feat-1">
                <FaCheckCircle className="text-lg text-blue-400 shrink-0" />
                <span className="text-sm font-medium text-slate-200">
                  Real-time Telemetry Ingestion (10,000+ Monitored Security Events)
                </span>
              </div>
              <div className="flex items-center gap-3 lgn-feat-2">
                <FaCheckCircle className="text-lg text-blue-400 shrink-0" />
                <span className="text-sm font-medium text-slate-200">
                  Supervised Risk &amp; ML Anomaly Detection (IsoForest + XGBoost Scoring Engine)
                </span>
              </div>
              <div className="flex items-center gap-3 lgn-feat-3">
                <FaCheckCircle className="text-lg text-blue-400 shrink-0" />
                <span className="text-sm font-medium text-slate-200">
                  Priority Incident Correlation (Enterprise Blast Radius &amp; Kill Chain)
                </span>
              </div>
              <div className="flex items-center gap-3 lgn-feat-4">
                <FaCheckCircle className="text-lg text-blue-400 shrink-0" />
                <span className="text-sm font-medium text-slate-200">
                  Explainable Recommendations (Automated SOC Playbooks &amp; Threat Intel)
                </span>
              </div>
            </div>
          </div>

          {/* ============================================================ */}
          {/* LOGIN CARD                                                     */}
          {/* ============================================================ */}
          <div className="lgn-card w-full max-w-md xl:max-w-lg rounded-2xl border border-slate-800 bg-slate-900/90 p-6 sm:p-8 shadow-2xl backdrop-blur-md">

            {/* Shield Logo */}
            <div className="flex justify-center">
              <div className="rounded-2xl bg-blue-600 p-3.5 shadow-xl lgn-shield-glow">
                <FaShieldAlt className="text-3xl text-white" />
              </div>
            </div>

            {/* Headings */}
            <div className="mt-4 text-center lgn-heading">
              <h2 className="text-2xl font-bold text-white tracking-tight">
                SentinelAI Security
              </h2>
              <p className="mt-1 text-xs text-slate-300 leading-snug">
                Access the Security Operations Center &bull; Risk Mitigation Analytics
              </p>
              <p className="mt-2 text-xs font-semibold text-blue-400 uppercase tracking-wider">
                Authorized SOC Analyst Login
              </p>
            </div>

            {/* Login Form */}
            <form onSubmit={handleLogin} className="mt-5 space-y-4" noValidate>

              {/* EMAIL */}
              <div>
                <label htmlFor="login-email" className="mb-1.5 block text-xs font-semibold text-slate-200">
                  Email Address
                </label>
                <div className="relative">
                  <FaUser className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400 text-sm" />
                  <input
                    id="login-email"
                    type="email"
                    value={email}
                    autoComplete="username"
                    onChange={(e) => { setEmail(e.target.value); setFormError(""); }}
                    placeholder="analyst@sentinelai.internal"
                    className="h-11 w-full rounded-xl border border-slate-700 bg-slate-950 pl-10 pr-4 text-sm text-white placeholder:text-slate-400 outline-none transition-all duration-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20"
                  />
                </div>
              </div>

              {/* PASSWORD */}
              <div>
                <label htmlFor="login-password" className="mb-1.5 block text-xs font-semibold text-slate-200">
                  Password
                </label>
                <div className="relative">
                  <FaLock className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400 text-sm" />
                  <input
                    id="login-password"
                    type={showPassword ? "text" : "password"}
                    value={password}
                    autoComplete="current-password"
                    onChange={(e) => { setPassword(e.target.value); setFormError(""); }}
                    placeholder="••••••••"
                    className="h-11 w-full rounded-xl border border-slate-700 bg-slate-950 pl-10 pr-11 text-sm text-white placeholder:text-slate-400 outline-none transition-all duration-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    aria-label={showPassword ? "Hide password" : "Show password"}
                    className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-400 transition hover:text-white"
                  >
                    {showPassword ? <FaEyeSlash className="text-sm" /> : <FaEye className="text-sm" />}
                  </button>
                </div>
              </div>

              {/* VALIDATION ERROR */}
              {formError && (
                <p id="login-error" className="text-xs font-medium text-red-400" role="alert">
                  {formError}
                </p>
              )}

              {/* REMEMBER / FORGOT */}
              <div className="flex items-center justify-between text-xs pt-0.5">
                <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    className="h-3.5 w-3.5 cursor-pointer rounded accent-blue-600"
                  />
                  <span className="font-medium text-slate-200">Remember Session</span>
                </label>
                <button
                  type="button"
                  className="font-medium text-blue-400 transition hover:text-blue-300"
                >
                  Forgot Password?
                </button>
              </div>

              {/* LOGIN BUTTON */}
              <button
                type="submit"
                disabled={submitting}
                className={`lgn-btn w-full rounded-xl bg-blue-600 py-2.5 text-sm font-semibold text-white shadow-lg transition-all duration-200 hover:bg-blue-500 hover:shadow-blue-600/40 active:scale-[0.98] cursor-pointer ${submitting ? "lgn-submitting" : ""}`}
              >
                {submitting ? "Accessing Dashboard…" : "Access Security Dashboard →"}
              </button>
            </form>

            {/* FOOTER */}
            <div className="mt-5 border-t border-slate-800 pt-3.5 text-center space-y-1">
              <p className="text-xs font-semibold text-slate-300">
                SentinelAI Security Operations Platform
              </p>
              <p className="text-[11px] text-slate-400 font-mono">
                SentinelAI SOC v4.0.0-PROD &bull; Authorized Security Personnel Only
              </p>
              <p className="text-[10px] text-slate-400">
                Active Telemetry Monitoring (10k Events) &bull; &copy; 2026 SentinelAI
              </p>
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}

export default Login;