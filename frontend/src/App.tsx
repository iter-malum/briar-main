import { Suspense, lazy } from 'react'
import { BrowserRouter, Routes, Route, Navigate, NavLink } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  LayoutDashboard, ShieldAlert, GitGraph, Key, Wrench,
  CalendarClock, FileBarChart,
} from 'lucide-react'

const Dashboard       = lazy(() => import('./pages/Dashboard'))
const ScanGraph       = lazy(() => import('./pages/ScanGraph'))
const Vulnerabilities = lazy(() => import('./pages/Vulnerabilities'))
const AuthSessions    = lazy(() => import('./pages/AuthSessions'))
const Tools           = lazy(() => import('./pages/Tools'))
const Schedules       = lazy(() => import('./pages/Schedules'))
const Report          = lazy(() => import('./pages/Report'))

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 10_000,
      retry: 2,
    },
  },
})

function Sidebar() {
  const base     = 'flex items-center gap-2 px-3 py-2 rounded-lg text-sm transition-colors'
  const active   = 'bg-briar-accent text-white'
  const inactive = 'text-slate-400 hover:text-slate-100 hover:bg-briar-border'

  return (
    <aside className="w-56 bg-briar-surface border-r border-briar-border flex flex-col shrink-0">
      {/* Logo */}
      <div className="px-4 py-5 border-b border-briar-border">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-lg bg-briar-accent flex items-center justify-center text-white font-bold text-sm">
            B
          </div>
          <span className="font-semibold text-slate-100">Briar</span>
          <span className="text-slate-500 text-xs ml-auto">v0.2</span>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 p-3 space-y-1">
        <NavLink to="/dashboard" className={({ isActive }) => `${base} ${isActive ? active : inactive}`}>
          <LayoutDashboard size={15} /> Dashboard
        </NavLink>
        <NavLink to="/auth" className={({ isActive }) => `${base} ${isActive ? active : inactive}`}>
          <Key size={15} /> Auth Sessions
        </NavLink>
        <NavLink to="/vulns" className={({ isActive }) => `${base} ${isActive ? active : inactive}`}>
          <ShieldAlert size={15} /> All Vulnerabilities
        </NavLink>
        <NavLink to="/tools" className={({ isActive }) => `${base} ${isActive ? active : inactive}`}>
          <Wrench size={15} /> Tools
        </NavLink>
        <NavLink to="/schedules" className={({ isActive }) => `${base} ${isActive ? active : inactive}`}>
          <CalendarClock size={15} /> Schedules
        </NavLink>

        {/* Divider */}
        <div className="border-t border-briar-border my-2" />

        {/* Context-free report link (goes to last completed scan if any) */}
        <p className="px-3 text-xs text-slate-600 uppercase tracking-wide pt-1">Reports</p>
        <NavLink to="/dashboard" className={`${base} ${inactive} opacity-60`}>
          <FileBarChart size={15} /> Open a scan → Report
        </NavLink>
      </nav>

      <div className="p-3 border-t border-briar-border">
        <p className="text-xs text-slate-600">DAST Automation Platform</p>
      </div>
    </aside>
  )
}

function Layout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-full">
      <Sidebar />
      <main className="flex-1 overflow-auto">{children}</main>
    </div>
  )
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Suspense
          fallback={
            <div className="flex items-center justify-center h-screen text-slate-500">
              Loading…
            </div>
          }
        >
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />

            {/* Full-screen graph — no sidebar */}
            <Route path="/scan/:id/graph" element={<ScanGraph />} />

            {/* Sidebar layout */}
            <Route
              path="*"
              element={
                <Layout>
                  <Routes>
                    <Route path="/dashboard"           element={<Dashboard />} />
                    <Route path="/auth"                element={<AuthSessions />} />
                    <Route path="/vulns"               element={<Vulnerabilities />} />
                    <Route path="/scan/:id/vulns"      element={<Vulnerabilities />} />
                    <Route path="/scan/:id/report"     element={<Report />} />
                    <Route path="/tools"               element={<Tools />} />
                    <Route path="/schedules"           element={<Schedules />} />
                    <Route path="*"                    element={<Navigate to="/dashboard" replace />} />
                  </Routes>
                </Layout>
              }
            />
          </Routes>
        </Suspense>
      </BrowserRouter>
    </QueryClientProvider>
  )
}
