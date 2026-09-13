import { NavLink } from "react-router-dom";
import {
  FiGrid,
  FiActivity,
  FiShield,
  FiLock,
  FiBarChart2,
  FiAlertTriangle,
  FiTrendingUp,
  FiGitCommit,
  FiLayers,
  FiPieChart,
  FiFileText,
} from "react-icons/fi";

const monitoringMenuItems = [
  { icon: FiGrid, label: "Overview", to: "/dashboard", end: true },
  { icon: FiShield, label: "AI Threat Detection", to: "/dashboard/detection" },
  { icon: FiActivity, label: "Security Events", to: "/dashboard/events" },
];

const investigationMenuItems = [
  { icon: FiTrendingUp, label: "Risk Overview", to: "/dashboard/risk-overview" },
  { icon: FiAlertTriangle, label: "Priority Incidents", to: "/dashboard/incidents" },
  { icon: FiGitCommit, label: "Attack Chains", to: "/dashboard/attack-chains" },
];

const intelligenceMenuItems = [
  { icon: FiLayers, label: "Threat Intelligence", to: "/dashboard/threat-intel" },
  { icon: FiLock, label: "Vulnerabilities", to: "/dashboard/vulnerabilities" },
  { icon: FiBarChart2, label: "Analytics", to: "/dashboard/analytics" },
];

const executiveMenuItems = [
  { icon: FiPieChart, label: "Executive Overview", to: "/dashboard/executive" },
  { icon: FiFileText, label: "Security Reports", to: "/dashboard/reports" },
];

const Sidebar = () => {
  return (
    <aside className="hidden lg:flex lg:w-56 xl:w-60 shrink-0 flex-col bg-[#020817] text-slate-200 border-r border-[#1F2937] select-none">
      {/* ================= Brand Header ================= */}
      <div className="border-b border-[#1F2937] px-4 py-4">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-600 shadow-md shadow-blue-900/40 shrink-0">
            <FiShield className="text-xl text-white" />
          </div>
          <div className="min-w-0">
            <h1 className="text-base font-bold tracking-tight text-slate-100 truncate">SentinelAI</h1>
            <p
              className="text-[10.5px] text-slate-400 font-medium truncate"
              title="Creation of Security Operations Dashboard for Threat Detection with Risk Mitigation Analytics"
            >
              Security Operations Dashboard
            </p>
          </div>
        </div>
      </div>

      {/* ================= Navigation ================= */}
      <nav className="flex-1 px-3 py-3 space-y-3.5 overflow-y-auto">
        {/* SOC Monitoring */}
        <div>
          <p className="mb-1.5 px-2 text-[10px] font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1">
            <span>SOC Monitoring</span>
          </p>
          <div className="space-y-0.5">
            {monitoringMenuItems.map((item) => (
              <NavLink
                key={item.label}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  `group flex items-center gap-2.5 rounded-lg px-3 py-1.5 text-xs font-semibold transition-all duration-200 ${
                    isActive
                      ? "bg-blue-600 text-white shadow-md shadow-blue-950/50"
                      : "text-slate-300 hover:bg-[#111827] hover:text-white"
                  }`
                }
              >
                <item.icon className="text-base shrink-0 transition-transform duration-200 group-hover:scale-110" />
                <span className="truncate">{item.label}</span>
              </NavLink>
            ))}
          </div>
        </div>

        {/* Risk & Investigation */}
        <div>
          <p className="mb-1.5 px-2 text-[10px] font-bold uppercase tracking-wider text-blue-400 flex items-center gap-1">
            <span>Risk & Investigation</span>
          </p>
          <div className="space-y-0.5">
            {investigationMenuItems.map((item) => (
              <NavLink
                key={item.label}
                to={item.to}
                className={({ isActive }) =>
                  `group flex items-center gap-2.5 rounded-lg px-3 py-1.5 text-xs font-semibold transition-all duration-200 ${
                    isActive
                      ? "bg-blue-600 text-white shadow-md shadow-blue-950/50"
                      : "text-slate-300 hover:bg-[#111827] hover:text-white"
                  }`
                }
              >
                <item.icon className="text-base shrink-0 transition-transform duration-200 group-hover:scale-110" />
                <span className="truncate">{item.label}</span>
              </NavLink>
            ))}
          </div>
        </div>

        {/* Intelligence */}
        <div>
          <p className="mb-1.5 px-2 text-[10px] font-bold uppercase tracking-wider text-slate-400">
            Intelligence
          </p>
          <div className="space-y-0.5">
            {intelligenceMenuItems.map((item) => (
              <NavLink
                key={item.label}
                to={item.to}
                className={({ isActive }) =>
                  `group flex items-center gap-2.5 rounded-lg px-3 py-1.5 text-xs font-semibold transition-all duration-200 ${
                    isActive
                      ? "bg-blue-600 text-white shadow-md shadow-blue-950/50"
                      : "text-slate-400 hover:bg-[#111827] hover:text-slate-200"
                  }`
                }
              >
                <item.icon className="text-base shrink-0 transition-transform duration-200 group-hover:scale-110" />
                <span className="truncate">{item.label}</span>
              </NavLink>
            ))}
          </div>
        </div>

        {/* Executive */}
        <div>
          <p className="mb-1.5 px-2 text-[10px] font-bold uppercase tracking-wider text-purple-400">
            Executive
          </p>
          <div className="space-y-0.5">
            {executiveMenuItems.map((item) => (
              <NavLink
                key={item.label}
                to={item.to}
                className={({ isActive }) =>
                  `group flex items-center gap-2.5 rounded-lg px-3 py-1.5 text-xs font-semibold transition-all duration-200 ${
                    isActive
                      ? "bg-blue-600 text-white shadow-md shadow-blue-950/50"
                      : "text-slate-400 hover:bg-[#111827] hover:text-slate-200"
                  }`
                }
              >
                <item.icon className="text-base shrink-0 transition-transform duration-200 group-hover:scale-110" />
                <span className="truncate">{item.label}</span>
              </NavLink>
            ))}
          </div>
        </div>
      </nav>

      {/* ================= Status Footer ================= */}
      <div className="border-t border-[#1F2937] p-3">
        <div className="rounded-lg bg-[#111827] border border-[#1F2937] p-2.5">
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span className="text-xs font-semibold text-slate-200">SentinelAI SOC Engine</span>
          </div>
          <div className="mt-1 text-[11px] text-slate-400 flex justify-between items-center">
            <span>AI Operations</span>
            <span className="text-emerald-400 font-mono text-[10px] font-bold">ONLINE</span>
          </div>
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;
