import { BrowserRouter, Routes, Route } from "react-router-dom";

import Login from "./pages/Login/Login";
import DashboardLayout from "./layouts/DashboardLayout";
import Overview from "./pages/Dashboard/Overview";
import ThreatDetection from "./pages/Dashboard/ThreatDetection";
import EventDetails from "./pages/Dashboard/EventDetails";
import SecurityEvents from "./pages/Dashboard/SecurityEvents";
import ThreatIntel from "./pages/Dashboard/ThreatIntel";
import Vulnerabilities from "./pages/Dashboard/Vulnerabilities";
import Analytics from "./pages/Dashboard/Analytics";
import RiskOverview from "./pages/Dashboard/RiskOverview";
import PriorityIncidents from "./pages/Dashboard/PriorityIncidents";
import IncidentDetails from "./pages/Dashboard/IncidentDetails";
import AttackChains from "./pages/Dashboard/AttackChains";
import Executive from "./pages/Dashboard/Executive";
import Reports from "./pages/Dashboard/Reports";

import { ThemeProvider } from "./context/ThemeContext";

function App() {
  return (
    <ThemeProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Login />} />
          <Route path="/dashboard" element={<DashboardLayout />}>
            <Route index element={<Overview />} />
            <Route path="risk-overview" element={<RiskOverview />} />
            <Route path="incidents" element={<PriorityIncidents />} />
            <Route path="incidents/:id" element={<IncidentDetails />} />
            <Route path="attack-chains" element={<AttackChains />} />
            <Route path="detection" element={<ThreatDetection />} />
            <Route path="events/:id" element={<EventDetails />} />
            <Route path="events" element={<SecurityEvents />} />
            <Route path="threat-intel" element={<ThreatIntel />} />
            <Route path="vulnerabilities" element={<Vulnerabilities />} />
            <Route path="analytics" element={<Analytics />} />
            <Route path="executive" element={<Executive />} />
            <Route path="reports" element={<Reports />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ThemeProvider>
  );
}

export default App;
