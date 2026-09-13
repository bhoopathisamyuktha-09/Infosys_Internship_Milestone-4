import { useState, useRef, useEffect } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import {
  FiSearch,
  FiBell,
  FiUser,
  FiCalendar,
  FiActivity,
  FiSun,
  FiMoon,
  FiMenu,
  FiX,
  FiGrid,
  FiAlertTriangle,
  FiShield,
  FiLock,
  FiBarChart2,
  FiTrendingUp,
  FiGitCommit,
  FiLayers,
  FiPieChart,
  FiFileText,
  FiLogOut,
  FiSettings,
  FiDatabase,
  FiArrowRight,
} from "react-icons/fi";
import { useTheme } from "../../context/ThemeContext";

const menuItems = [
  { icon: FiGrid, label: "Overview", to: "/dashboard" },
  { icon: FiShield, label: "AI Threat Detection", to: "/dashboard/detection" },
  { icon: FiActivity, label: "Security Events", to: "/dashboard/events" },
  { icon: FiTrendingUp, label: "Risk Overview", to: "/dashboard/risk-overview" },
  { icon: FiAlertTriangle, label: "Priority Incidents", to: "/dashboard/incidents" },
  { icon: FiGitCommit, label: "Attack Chains", to: "/dashboard/attack-chains" },
  { icon: FiLayers, label: "Threat Intelligence", to: "/dashboard/threat-intel" },
  { icon: FiLock, label: "Vulnerabilities", to: "/dashboard/vulnerabilities" },
  { icon: FiBarChart2, label: "Analytics", to: "/dashboard/analytics" },
  { icon: FiPieChart, label: "Executive Overview", to: "/dashboard/executive" },
  { icon: FiFileText, label: "Security Reports", to: "/dashboard/reports" },
];

// Predefined catalog of primary telemetry entities for instant search
const SEARCH_ENTITIES = [
  { type: "threat", name: "Brute Force", category: "Credential Access", link: "/dashboard/incidents?threat_type=Brute+Force" },
  { type: "threat", name: "Privilege Escalation", category: "Privilege Escalation", link: "/dashboard/incidents?threat_type=Privilege+Escalation" },
  { type: "threat", name: "SQL Injection Attempt", category: "Initial Access", link: "/dashboard/incidents?threat_type=SQL+Injection+Attempt" },
  { type: "threat", name: "Failed Login", category: "Defense Evasion", link: "/dashboard/incidents?threat_type=Failed+Login" },
  { type: "threat", name: "Data Exfiltration", category: "Exfiltration", link: "/dashboard/incidents?threat_type=Data+Exfiltration" },
  { type: "asset", name: "Database-01", category: "Critical Asset (IT)", link: "/dashboard/incidents?asset_name=Database-01" },
  { type: "asset", name: "WebServer", category: "Critical Asset (IT)", link: "/dashboard/incidents?asset_name=WebServer" },
  { type: "asset", name: "Finance-PC-02", category: "High Asset (Finance)", link: "/dashboard/incidents?asset_name=Finance-PC-02" },
  { type: "asset", name: "HR-PC-01", category: "Medium Asset (HR)", link: "/dashboard/incidents?asset_name=HR-PC-01" },
  { type: "cve", name: "CVE-2024-1045", category: "Critical CVSS 9.5", link: "/dashboard/vulnerabilities?search=CVE-2024-1045" },
  { type: "cve", name: "CVE-2023-1234", category: "High CVSS 8.4", link: "/dashboard/vulnerabilities?search=CVE-2023-1234" },
  { type: "cve", name: "CVE-2024-2201", category: "Medium CVSS 5.9", link: "/dashboard/vulnerabilities?search=CVE-2024-2201" },
  { type: "cve", name: "CVE-2024-43099", category: "Critical CVSS 9.8", link: "/dashboard/vulnerabilities?search=CVE-2024-43099" },
  { type: "ioc", name: "192.0.2.1", category: "Malicious IP Indicator", link: "/dashboard/threat-intel?search=192.0.2.1" },
  { type: "ioc", name: "198.51.100.1", category: "Malicious IP Indicator", link: "/dashboard/threat-intel?search=198.51.100.1" },
  { type: "incident", name: "INC-000001", category: "Critical Incident — Database-01", link: "/dashboard/incidents/INC-000001" },
  { type: "incident", name: "INC-000058", category: "Critical Incident — WebServer", link: "/dashboard/incidents/INC-000058" },
  { type: "event", name: "EVT000001", category: "Brute Force Security Event", link: "/dashboard/events/EVT000001" },
  { type: "event", name: "EVT000002", category: "Privilege Escalation Event", link: "/dashboard/events/EVT000002" },
  { type: "asset", name: "Firewall", category: "Critical Asset (Network)", link: "/dashboard/incidents?asset_name=Firewall" },
];

const Header = () => {
  const { toggleTheme, isDark } = useTheme();
  const navigate = useNavigate();

  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);

  // Global search state
  const [searchQuery, setSearchQuery] = useState("");
  const [searchFocused, setSearchFocused] = useState(false);

  const searchContainerRef = useRef(null);
  const notifRef = useRef(null);
  const profileRef = useRef(null);

  // Close dropdowns when clicking outside
  useEffect(() => {
    function handleClickOutside(event) {
      if (searchContainerRef.current && !searchContainerRef.current.contains(event.target)) {
        setSearchFocused(false);
      }
      if (notifRef.current && !notifRef.current.contains(event.target)) {
        setNotificationsOpen(false);
      }
      if (profileRef.current && !profileRef.current.contains(event.target)) {
        setProfileOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  // Compute search matches
  const trimmedQuery = searchQuery.trim().toLowerCase();
  const searchResults = trimmedQuery
    ? SEARCH_ENTITIES.filter(
        (item) =>
          item.name.toLowerCase().includes(trimmedQuery) ||
          item.category.toLowerCase().includes(trimmedQuery) ||
          item.type.toLowerCase().includes(trimmedQuery)
      )
    : [];

  // If query is an incident or event ID not in the static sample, create dynamic match
  const isCustomIncident = /^inc-\d+/i.test(trimmedQuery);
  const isCustomEvent = /^evt\d+/i.test(trimmedQuery);

  const handleSelectResult = (link) => {
    setSearchQuery("");
    setSearchFocused(false);
    navigate(link);
  };

  const handleLogout = () => {
    setProfileOpen(false);
    navigate("/login");
  };

  return (
    <header className={`border-b px-4 md:px-6 py-3 select-none relative z-30 transition-colors ${
      isDark ? "bg-[#0B1329] border-[#1F2937]" : "bg-white border-slate-200 shadow-xs"
    }`}>
      {/* Top Row: Title + Status Chips & Controls */}
      <div className="flex items-center justify-between gap-3">
        {/* Left Side: Title & Subtitle + Mobile Toggle */}
        <div className="flex items-center gap-3 min-w-0">
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label="Toggle mobile menu"
            className={`lg:hidden flex h-8 w-8 items-center justify-center rounded-lg border transition-colors ${
              isDark
                ? "border-[#1F2937] bg-[#111827] text-slate-300 hover:text-white"
                : "border-slate-300 bg-slate-100 text-slate-700 hover:text-slate-900"
            }`}
          >
            {mobileMenuOpen ? <FiX className="text-base" /> : <FiMenu className="text-base" />}
          </button>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h1 className={`text-base md:text-xl font-extrabold tracking-tight truncate ${
                isDark ? "text-slate-100" : "text-slate-900"
              }`}>
                SentinelAI Operations
              </h1>
              <span className={`hidden xl:inline-block px-2 py-0.5 rounded text-[10px] font-bold font-mono border ${
                isDark ? "bg-blue-500/20 text-blue-300 border-blue-500/30" : "bg-blue-50 text-blue-700 border-blue-200"
              }`}>
                SOC PLATFORM
              </span>
            </div>
            <p
              className={`hidden sm:block text-[11px] md:text-xs font-medium truncate ${
                isDark ? "text-slate-400" : "text-slate-600"
              }`}
              title="Creation of Security Operations Dashboard for Threat Detection with Risk Mitigation Analytics"
            >
              Creation of Security Operations Dashboard for Threat Detection with Risk Mitigation Analytics
            </p>
          </div>

          {/* Status & Historical Telemetry Clarity Chips */}
          <div className="hidden lg:flex items-center gap-2 ml-2">
            <div className={`flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-medium ${
              isDark ? "border-[#1F2937] bg-[#111827] text-slate-300" : "border-slate-200 bg-slate-50 text-slate-700"
            }`}>
              <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse"></span>
              <span>System Online</span>
            </div>
            <div
              className={`flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-medium ${
                isDark ? "border-[#1F2937] bg-[#111827] text-slate-300" : "border-slate-200 bg-slate-50 text-slate-700"
              }`}
              title="Current active system evaluation timestamp"
            >
              <FiCalendar className={`text-xs ${isDark ? "text-blue-400" : "text-blue-600"}`} />
              <span>System: {new Date().toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}</span>
            </div>
            <div
              className={`flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-xs font-medium ${
                isDark
                  ? "border-purple-500/30 bg-purple-500/10 text-purple-300"
                  : "border-purple-200 bg-purple-50 text-purple-700"
              }`}
              title="Underlying security events dataset is from the baseline telemetry archive"
            >
              <FiDatabase className={`text-xs ${isDark ? "text-purple-400" : "text-purple-600"}`} />
              <span>Telemetry: Aug 2025 Archive</span>
            </div>
          </div>
        </div>

        {/* Right Side: Theme Toggle, Notifications, Profile */}
        <div className="flex items-center gap-2 shrink-0">
          {/* Theme Toggle */}
          <button
            onClick={toggleTheme}
            title={isDark ? "Switch to Light Mode" : "Switch to Dark Mode"}
            aria-label={isDark ? "Switch to Light Mode" : "Switch to Dark Mode"}
            className={`flex h-8 w-8 items-center justify-center rounded-lg border transition-all duration-200 cursor-pointer ${
              isDark
                ? "border-[#1F2937] bg-[#111827] text-slate-300 hover:text-white hover:border-slate-700"
                : "border-slate-300 bg-slate-100 text-slate-700 hover:text-slate-900 hover:border-slate-400"
            }`}
          >
            {isDark ? <FiSun className="text-sm text-amber-400" /> : <FiMoon className="text-sm text-blue-600" />}
          </button>

          {/* Notification Bell Dropdown */}
          <div className="relative" ref={notifRef}>
            <button
              onClick={() => {
                setNotificationsOpen(!notificationsOpen);
                setProfileOpen(false);
              }}
              title="Security Alerts & Notifications"
              aria-label="Security Alerts & Notifications"
              className={`relative flex h-8 w-8 items-center justify-center rounded-lg border transition-all duration-200 cursor-pointer ${
                isDark
                  ? "border-[#1F2937] bg-[#111827] text-slate-300 hover:text-white hover:border-slate-700"
                  : "border-slate-300 bg-slate-100 text-slate-700 hover:text-slate-900 hover:border-slate-400"
              }`}
            >
              <FiBell className="text-sm" />
              <span className={`absolute top-1.5 right-1.5 h-2 w-2 rounded-full bg-red-500 ring-2 animate-pulse ${
                isDark ? "ring-[#111827]" : "ring-white"
              }`}></span>
            </button>

            {notificationsOpen && (
              <div className={`absolute right-0 mt-2 w-[calc(100vw-2rem)] sm:w-96 max-w-sm rounded-xl border shadow-2xl z-50 overflow-hidden text-xs anim-fade-card ${
                isDark ? "border-[#1F2937] bg-[#111827]" : "border-slate-200 bg-white shadow-xl"
              }`}>
                <div className={`p-3 border-b flex items-center justify-between ${
                  isDark ? "border-[#1F2937] bg-[#1E293B]/40" : "border-slate-200 bg-slate-50"
                }`}>
                  <div className="flex items-center gap-2">
                    <FiAlertTriangle className={isDark ? "text-amber-400" : "text-amber-600"} />
                    <span className={`font-bold ${isDark ? "text-slate-100" : "text-slate-900"}`}>Security Alerts</span>
                  </div>
                  <span className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold border ${
                    isDark ? "bg-red-500/20 text-red-300 border-red-500/30" : "bg-red-50 text-red-700 border-red-200"
                  }`}>
                    3 ACTIONABLE
                  </span>
                </div>

                <div className={`divide-y max-h-[300px] overflow-y-auto ${
                  isDark ? "divide-[#1F2937]" : "divide-slate-200"
                }`}>
                  <div
                    onClick={() => {
                      setNotificationsOpen(false);
                      navigate("/dashboard/incidents?risk_level=Critical");
                    }}
                    className={`p-3 transition-colors cursor-pointer space-y-1 ${
                      isDark ? "hover:bg-[#1E293B]/50" : "hover:bg-slate-50"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className={`font-bold flex items-center gap-1.5 ${isDark ? "text-red-400" : "text-red-600"}`}>
                        <span className="h-1.5 w-1.5 rounded-full bg-red-500"></span>
                        Critical Incidents Require SLA Triage
                      </span>
                      <span className={`text-[10px] ${isDark ? "text-slate-500" : "text-slate-400"}`}>Immediate</span>
                    </div>
                    <p className={`text-[11px] ${isDark ? "text-slate-300" : "text-slate-600"}`}>
                      109 Critical security incidents flagged by the risk engine on core infrastructure.
                    </p>
                  </div>

                  <div
                    onClick={() => {
                      setNotificationsOpen(false);
                      navigate("/dashboard/vulnerabilities?severity=Critical");
                    }}
                    className={`p-3 transition-colors cursor-pointer space-y-1 ${
                      isDark ? "hover:bg-[#1E293B]/50" : "hover:bg-slate-50"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className={`font-bold flex items-center gap-1.5 ${isDark ? "text-amber-400" : "text-amber-600"}`}>
                        <span className="h-1.5 w-1.5 rounded-full bg-amber-500"></span>
                        High-Severity CVE Exposure
                      </span>
                      <span className={`text-[10px] ${isDark ? "text-slate-500" : "text-slate-400"}`}>Patches Pending</span>
                    </div>
                    <p className={`text-[11px] ${isDark ? "text-slate-300" : "text-slate-600"}`}>
                      113 Critical CVEs identified on Database-01 & WebServer requiring patch deployment.
                    </p>
                  </div>

                  <div
                    onClick={() => {
                      setNotificationsOpen(false);
                      navigate("/dashboard/attack-chains");
                    }}
                    className={`p-3 transition-colors cursor-pointer space-y-1 ${
                      isDark ? "hover:bg-[#1E293B]/50" : "hover:bg-slate-50"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className={`font-bold flex items-center gap-1.5 ${isDark ? "text-purple-400" : "text-purple-600"}`}>
                        <span className="h-1.5 w-1.5 rounded-full bg-purple-500"></span>
                        Multi-Stage Attack Progression
                      </span>
                      <span className={`text-[10px] ${isDark ? "text-slate-500" : "text-slate-400"}`}>Correlated</span>
                    </div>
                    <p className={`text-[11px] ${isDark ? "text-slate-300" : "text-slate-600"}`}>
                      4,196 correlated multi-stage attack chains identified across enterprise endpoints.
                    </p>
                  </div>
                </div>

                <div className={`p-2.5 border-t text-center ${
                  isDark ? "border-[#1F2937] bg-[#1E293B]/20" : "border-slate-200 bg-slate-50"
                }`}>
                  <button
                    onClick={() => {
                      setNotificationsOpen(false);
                      navigate("/dashboard/incidents");
                    }}
                    className={`text-xs font-semibold flex items-center justify-center gap-1 w-full cursor-pointer ${
                      isDark ? "text-blue-400 hover:text-blue-300" : "text-blue-600 hover:text-blue-700"
                    }`}
                  >
                    <span>View Priority Incidents Queue</span>
                    <FiArrowRight />
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* SOC Analyst Profile Dropdown */}
          <div className="relative" ref={profileRef}>
            <div
              onClick={() => {
                setProfileOpen(!profileOpen);
                setNotificationsOpen(false);
              }}
              className={`flex items-center gap-2 rounded-lg border px-2.5 py-1.5 text-xs font-medium transition-all duration-200 cursor-pointer ${
                isDark
                  ? "border-[#1F2937] bg-[#111827] text-slate-200 hover:border-slate-700"
                  : "border-slate-200 bg-slate-50 text-slate-800 hover:border-slate-300"
              }`}
            >
              <div className="flex h-5 w-5 items-center justify-center rounded-full bg-blue-600 text-white text-[10px] shrink-0 font-bold">
                <FiUser />
              </div>
              <span className="font-semibold hidden sm:inline">SOC Analyst</span>
              <span className="text-[10px] text-slate-400">▼</span>
            </div>

            {profileOpen && (
              <div className={`absolute right-0 mt-2 w-56 rounded-xl border shadow-2xl z-50 overflow-hidden text-xs anim-fade-card ${
                isDark ? "border-[#1F2937] bg-[#111827]" : "border-slate-200 bg-white shadow-xl"
              }`}>
                <div className={`p-3 border-b ${
                  isDark ? "border-[#1F2937] bg-[#1E293B]/40" : "border-slate-200 bg-slate-50"
                }`}>
                  <p className={`font-bold ${isDark ? "text-slate-100" : "text-slate-900"}`}>SOC Analyst</p>
                  <p className={`text-[11px] mt-0.5 ${isDark ? "text-slate-400" : "text-slate-500"}`}>Role: Security Operations Analyst</p>
                  <span className={`inline-block mt-1.5 px-2 py-0.5 rounded text-[10px] font-mono border ${
                    isDark ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" : "bg-emerald-50 text-emerald-700 border-emerald-200"
                  }`}>
                    Tier-2 Incident Response
                  </span>
                </div>

                <div className="p-1.5 space-y-0.5">
                  <button
                    onClick={() => {
                      setProfileOpen(false);
                      navigate("/dashboard/risk-overview");
                    }}
                    className={`w-full flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg text-left transition-colors cursor-pointer ${
                      isDark ? "text-slate-300 hover:bg-[#1E293B] hover:text-white" : "text-slate-700 hover:bg-slate-100 hover:text-slate-900"
                    }`}
                  >
                    <FiShield className={isDark ? "text-blue-400" : "text-blue-600"} />
                    <span>Analyst Risk Dashboard</span>
                  </button>

                  <button
                    onClick={() => {
                      setProfileOpen(false);
                      toggleTheme();
                    }}
                    className={`w-full flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg text-left transition-colors cursor-pointer ${
                      isDark ? "text-slate-300 hover:bg-[#1E293B] hover:text-white" : "text-slate-700 hover:bg-slate-100 hover:text-slate-900"
                    }`}
                  >
                    <FiSettings className={isDark ? "text-slate-400" : "text-slate-500"} />
                    <span>Interface: {isDark ? "Dark Theme" : "Light Theme"}</span>
                  </button>
                </div>

                <div className={`p-1.5 border-t ${isDark ? "border-[#1F2937]" : "border-slate-200"}`}>
                  <button
                    onClick={handleLogout}
                    className="w-full flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg text-red-500 hover:bg-red-500/10 text-left font-semibold transition-colors cursor-pointer"
                  >
                    <FiLogOut />
                    <span>Sign Out / Lock Session</span>
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Global Interactive Search Bar */}
      <div className="mt-2.5 relative" ref={searchContainerRef}>
        <div className={`flex items-center rounded-lg border px-3 py-1.5 transition-all duration-200 focus-within:border-blue-500 focus-within:ring-1 focus-within:ring-blue-500/20 ${
          isDark ? "border-[#1F2937] bg-[#111827]" : "border-slate-300 bg-white shadow-xs"
        }`}>
          <FiSearch className="text-sm text-slate-400 shrink-0" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            onFocus={() => setSearchFocused(true)}
            onKeyDown={(e) => {
              if (e.key === "Escape") {
                setSearchFocused(false);
              } else if (e.key === "Enter" && trimmedQuery) {
                const isCustomCve = /^cve-\d{4}-\d+/i.test(trimmedQuery);
                if (isCustomIncident) {
                  handleSelectResult(`/dashboard/incidents/${trimmedQuery.toUpperCase()}`);
                } else if (isCustomEvent) {
                  handleSelectResult(`/dashboard/events/${trimmedQuery.toUpperCase()}`);
                } else if (isCustomCve) {
                  handleSelectResult(`/dashboard/vulnerabilities?search=${trimmedQuery.toUpperCase()}`);
                } else if (searchResults.length > 0) {
                  handleSelectResult(searchResults[0].link);
                } else {
                  handleSelectResult(`/dashboard/incidents?threat_type=${encodeURIComponent(trimmedQuery)}`);
                }
              }
            }}
            placeholder="Search security events, incident IDs (INC-), CVEs, threat types, or assets..."
            className={`ml-2 w-full bg-transparent text-xs focus:outline-none ${
              isDark ? "text-slate-200 placeholder:text-slate-500" : "text-slate-900 placeholder:text-slate-400"
            }`}
          />
          {searchQuery && (
            <button
              type="button"
              onClick={() => setSearchQuery("")}
              className="text-slate-500 hover:text-slate-300 text-xs shrink-0 cursor-pointer"
            >
              <FiX />
            </button>
          )}
        </div>

        {/* Search Results Dropdown */}
        {searchFocused && trimmedQuery && (
          <div className={`absolute left-0 right-0 mt-1.5 rounded-xl border shadow-2xl z-50 overflow-hidden text-xs anim-fade-card max-h-[360px] overflow-y-auto ${
            isDark ? "border-[#1F2937] bg-[#111827]" : "border-slate-200 bg-white shadow-xl"
          }`}>
            {/* Dynamic direct ID match if applicable */}
            {isCustomIncident && (
              <div
                onClick={() => handleSelectResult(`/dashboard/incidents/${trimmedQuery.toUpperCase()}`)}
                className={`p-3 cursor-pointer flex items-center justify-between border-b ${
                  isDark ? "hover:bg-[#1E293B] border-[#1F2937]" : "hover:bg-slate-100 border-slate-200"
                }`}
              >
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 rounded font-mono font-bold text-[10px] border ${
                    isDark ? "bg-blue-500/20 text-blue-300 border-blue-500/30" : "bg-blue-50 text-blue-700 border-blue-200"
                  }`}>
                    INCIDENT
                  </span>
                  <span className={`font-bold font-mono ${isDark ? "text-slate-100" : "text-slate-900"}`}>{trimmedQuery.toUpperCase()}</span>
                </div>
                <span className={`flex items-center gap-1 font-semibold ${isDark ? "text-blue-400" : "text-blue-600"}`}>
                  <span>Open Triage</span>
                  <FiArrowRight />
                </span>
              </div>
            )}

            {isCustomEvent && (
              <div
                onClick={() => handleSelectResult(`/dashboard/events/${trimmedQuery.toUpperCase()}`)}
                className={`p-3 cursor-pointer flex items-center justify-between border-b ${
                  isDark ? "hover:bg-[#1E293B] border-[#1F2937]" : "hover:bg-slate-100 border-slate-200"
                }`}
              >
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 rounded font-mono font-bold text-[10px] border ${
                    isDark ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/30" : "bg-emerald-50 text-emerald-700 border-emerald-200"
                  }`}>
                    EVENT
                  </span>
                  <span className={`font-bold font-mono ${isDark ? "text-slate-100" : "text-slate-900"}`}>{trimmedQuery.toUpperCase()}</span>
                </div>
                <span className={`flex items-center gap-1 font-semibold ${isDark ? "text-emerald-400" : "text-emerald-600"}`}>
                  <span>Inspect Event</span>
                  <FiArrowRight />
                </span>
              </div>
            )}

            {/* Catalog matches */}
            {searchResults.length > 0 ? (
              <div className={`divide-y ${isDark ? "divide-[#1F2937]" : "divide-slate-200"}`}>
                {searchResults.map((res, idx) => (
                  <div
                    key={idx}
                    onClick={() => handleSelectResult(res.link)}
                    className={`p-2.5 cursor-pointer flex items-center justify-between transition-colors ${
                      isDark ? "hover:bg-[#1E293B]/70" : "hover:bg-slate-50"
                    }`}
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      <span
                        className={`px-2 py-0.5 rounded font-mono font-bold text-[10px] shrink-0 uppercase border ${
                          res.type === "incident"
                            ? (isDark ? "bg-red-500/20 text-red-300 border-red-500/30" : "bg-red-50 text-red-700 border-red-200")
                            : res.type === "threat"
                            ? (isDark ? "bg-purple-500/20 text-purple-300 border-purple-500/30" : "bg-purple-50 text-purple-700 border-purple-200")
                            : res.type === "cve"
                            ? (isDark ? "bg-amber-500/20 text-amber-300 border-amber-500/30" : "bg-amber-50 text-amber-700 border-amber-200")
                            : res.type === "asset"
                            ? (isDark ? "bg-blue-500/20 text-blue-300 border-blue-500/30" : "bg-blue-50 text-blue-700 border-blue-200")
                            : (isDark ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/30" : "bg-emerald-50 text-emerald-700 border-emerald-200")
                        }`}
                      >
                        {res.type}
                      </span>
                      <div className="truncate">
                        <span className={`font-semibold block truncate ${isDark ? "text-slate-200" : "text-slate-900"}`}>{res.name}</span>
                        <span className={`text-[10px] block truncate ${isDark ? "text-slate-400" : "text-slate-500"}`}>{res.category}</span>
                      </div>
                    </div>

                    <span className="text-slate-400 hover:text-white shrink-0 ml-2">
                      <FiArrowRight />
                    </span>
                  </div>
                ))}
              </div>
            ) : !isCustomIncident && !isCustomEvent ? (
              <div className="p-4 text-center text-slate-400">
                <p>No matching entities found for "{searchQuery}".</p>
                <button
                  type="button"
                  onClick={() => handleSelectResult(`/dashboard/incidents?threat_type=${encodeURIComponent(trimmedQuery)}`)}
                  className="mt-2 text-xs text-blue-400 hover:underline inline-flex items-center gap-1"
                >
                  <span>Filter Incidents by "{searchQuery}"</span>
                  <FiArrowRight />
                </button>
              </div>
            ) : null}
          </div>
        )}
      </div>

      {/* Mobile Navigation Drawer with Backdrop Overlay */}
      {mobileMenuOpen && (
        <>
          {/* Backdrop */}
          <div
            onClick={() => setMobileMenuOpen(false)}
            className="fixed inset-0 bg-black/60 backdrop-blur-xs z-40 lg:hidden transition-opacity"
            aria-hidden="true"
          />

          {/* Slide-out Drawer */}
          <aside
            className={`fixed inset-y-0 left-0 w-72 max-w-[85vw] z-50 lg:hidden shadow-2xl flex flex-col border-r select-none transition-transform duration-300 ${
              isDark ? "bg-[#020817] text-slate-200 border-[#1F2937]" : "bg-white text-slate-900 border-slate-200"
            }`}
          >
            {/* Drawer Header */}
            <div className={`p-4 border-b flex items-center justify-between ${isDark ? "border-[#1F2937]" : "border-slate-200"}`}>
              <div className="flex items-center gap-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-600 shadow-md shadow-blue-900/40 shrink-0">
                  <FiShield className="text-xl text-white" />
                </div>
                <div>
                  <h2 className={`text-base font-bold tracking-tight ${isDark ? "text-slate-100" : "text-slate-900"}`}>SentinelAI</h2>
                  <p className={`text-[10.5px] font-medium ${isDark ? "text-slate-400" : "text-slate-500"}`}>SOC Operations</p>
                </div>
              </div>
              <button
                onClick={() => setMobileMenuOpen(false)}
                aria-label="Close navigation drawer"
                className={`p-1.5 rounded-lg border transition-colors cursor-pointer ${
                  isDark
                    ? "border-[#1F2937] hover:bg-[#111827] text-slate-400 hover:text-white"
                    : "border-slate-200 hover:bg-slate-100 text-slate-600 hover:text-slate-900"
                }`}
              >
                <FiX className="text-lg" />
              </button>
            </div>

            {/* Nav Items Grouped into 4 Tiers */}
            <nav className="flex-1 px-3 py-3 space-y-3.5 overflow-y-auto">
              {/* 1. SOC Monitoring */}
              <div>
                <p className="mb-1 px-2 text-[10px] font-bold uppercase tracking-wider text-slate-400">SOC Monitoring</p>
                <div className="space-y-0.5">
                  {menuItems.slice(0, 3).map((item) => (
                    <NavLink
                      key={item.label}
                      to={item.to}
                      end={item.to === "/dashboard"}
                      onClick={() => setMobileMenuOpen(false)}
                      className={({ isActive }) =>
                        `flex items-center gap-2.5 rounded-lg px-3 py-2 text-xs font-semibold transition-colors ${
                          isActive
                            ? "bg-blue-600 text-white shadow-md shadow-blue-950/50"
                            : isDark
                            ? "text-slate-300 hover:bg-[#111827] hover:text-white"
                            : "text-slate-700 hover:bg-slate-100 hover:text-slate-900"
                        }`
                      }
                    >
                      <item.icon className="text-base shrink-0" />
                      <span>{item.label}</span>
                    </NavLink>
                  ))}
                </div>
              </div>

              {/* 2. Risk & Investigation */}
              <div>
                <p className="mb-1 px-2 text-[10px] font-bold uppercase tracking-wider text-blue-400">Risk & Investigation</p>
                <div className="space-y-0.5">
                  {menuItems.slice(3, 6).map((item) => (
                    <NavLink
                      key={item.label}
                      to={item.to}
                      onClick={() => setMobileMenuOpen(false)}
                      className={({ isActive }) =>
                        `flex items-center gap-2.5 rounded-lg px-3 py-2 text-xs font-semibold transition-colors ${
                          isActive
                            ? "bg-blue-600 text-white shadow-md shadow-blue-950/50"
                            : isDark
                            ? "text-slate-300 hover:bg-[#111827] hover:text-white"
                            : "text-slate-700 hover:bg-slate-100 hover:text-slate-900"
                        }`
                      }
                    >
                      <item.icon className="text-base shrink-0" />
                      <span>{item.label}</span>
                    </NavLink>
                  ))}
                </div>
              </div>

              {/* 3. Intelligence */}
              <div>
                <p className="mb-1 px-2 text-[10px] font-bold uppercase tracking-wider text-slate-400">Intelligence</p>
                <div className="space-y-0.5">
                  {menuItems.slice(6, 9).map((item) => (
                    <NavLink
                      key={item.label}
                      to={item.to}
                      onClick={() => setMobileMenuOpen(false)}
                      className={({ isActive }) =>
                        `flex items-center gap-2.5 rounded-lg px-3 py-2 text-xs font-semibold transition-colors ${
                          isActive
                            ? "bg-blue-600 text-white shadow-md shadow-blue-950/50"
                            : isDark
                            ? "text-slate-300 hover:bg-[#111827] hover:text-white"
                            : "text-slate-700 hover:bg-slate-100 hover:text-slate-900"
                        }`
                      }
                    >
                      <item.icon className="text-base shrink-0" />
                      <span>{item.label}</span>
                    </NavLink>
                  ))}
                </div>
              </div>

              {/* 4. Executive */}
              <div>
                <p className="mb-1 px-2 text-[10px] font-bold uppercase tracking-wider text-purple-400">Executive</p>
                <div className="space-y-0.5">
                  {menuItems.slice(9, 11).map((item) => (
                    <NavLink
                      key={item.label}
                      to={item.to}
                      onClick={() => setMobileMenuOpen(false)}
                      className={({ isActive }) =>
                        `flex items-center gap-2.5 rounded-lg px-3 py-2 text-xs font-semibold transition-colors ${
                          isActive
                            ? "bg-blue-600 text-white shadow-md shadow-blue-950/50"
                            : isDark
                            ? "text-slate-300 hover:bg-[#111827] hover:text-white"
                            : "text-slate-700 hover:bg-slate-100 hover:text-slate-900"
                        }`
                      }
                    >
                      <item.icon className="text-base shrink-0" />
                      <span>{item.label}</span>
                    </NavLink>
                  ))}
                </div>
              </div>
            </nav>

            {/* Status Footer */}
            <div className={`p-3 border-t ${isDark ? "border-[#1F2937]" : "border-slate-200"}`}>
              <div className={`rounded-lg p-2.5 border ${isDark ? "bg-[#111827] border-[#1F2937]" : "bg-slate-50 border-slate-200"}`}>
                <div className="flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse"></span>
                  <span className={`text-xs font-semibold ${isDark ? "text-slate-200" : "text-slate-800"}`}>SentinelAI SOC Engine</span>
                </div>
                <div className="mt-1 text-[11px] text-slate-400 flex justify-between items-center">
                  <span>AI Operations</span>
                  <span className="text-emerald-500 font-mono text-[10px] font-bold">ONLINE</span>
                </div>
              </div>
            </div>
          </aside>
        </>
      )}
    </header>
  );
};

export default Header;