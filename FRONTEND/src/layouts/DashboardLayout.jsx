import { Outlet } from "react-router-dom";
import Sidebar from "../components/layout/Sidebar";
import Header from "../components/layout/Header";

export default function DashboardLayout() {
  return (
    <div className="flex h-screen bg-[#0F172A] text-slate-100 overflow-hidden font-sans antialiased">
      <Sidebar />
      <div className="flex flex-1 flex-col min-w-0 bg-[#0F172A]">
        <Header />
        <main className="flex-1 overflow-y-auto p-4 md:p-5">
          <div className="mx-auto max-w-[1600px]">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}

