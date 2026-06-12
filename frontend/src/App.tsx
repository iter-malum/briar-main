import { Suspense, lazy } from 'react'
import {
  BrowserRouter, Routes, Route, Navigate, NavLink, useMatch,
} from 'react-router-dom'
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query'
import {
  LayoutDashboard, ShieldAlert, GitGraph, Key, Wrench,
  CalendarClock, FileBarChart, Wifi, WifiOff,
} from 'lucide-react'
import { fetchScan } from './api/client'
import { StatusBadge } from './components/StatusBadge'

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

// ── Scan context panel ─────────────────────────────────────────────────────────
// Shows a sticky mini-card in the sidebar when the user is viewing a specific scan.

function ScanContextPanel() {
  const matchGraph  = useMatch('/scan/:id/graph')
  const matchVulns  = useMatch('/scan/:id/vulns')
  const matchReport = useMatch('/scan/:id/report')
  const match = matchGraph ?? matchVulns ?? matchReport
  const id = match?.params?.id

  const { data: scan } = useQuery({
    queryKey: ['scan', id],
    queryFn:  () => fetchScan(id!),
    enabled:  !!id,
    refetchInterval: 6000,
  })

  if (!id || !scan) return null

  const isRunning = scan.status === 'running'
  const runningTool = scan.steps.find(s => s.status === 'running')?.tool

  // Shorten target for display
  let displayTarget = scan.target_url
  try {
    const u = new URL(scan.target_url)
    displayTarget = u.hostname + (u.pathname !== '/' ? u.pathname : '')
  } catch { /* keep raw */ }

  return (
    <div className="mx-3 mb-3 rounded-lg border border-briar-border bg-briar-bg overflow-hidden">
      {/* amber top bar — progress indicator */}
      {isRunning && (
        <div className="h-0.5 w-full bg-briar-border overflow-hidden">
          <div className="h-full bg-briar-accent animate-pulse w-1/2" />
        </div>
      )}

      <div className="p-2.5 space-y-2">
        {/* target + status */}
        <div className="flex items-start gap-1.5">
          <div
            className={`mt-0.5 w-2 h-2 rounded-full shrink-0 ${
              isRunning
                ? 'bg-amber-400 animate-pulse'
                : scan.status === 'completed'
                ? 'bg-emerald-500'
                : scan.status === 'failed'
                ? 'bg-red-500'
                : 'bg-slate-600'
            }`}
          />
          <span
            className="text-xs text-slate-300 leading-tight break-all font-mono"
            title={scan.target_url}
          >
            {displayTarget.length > 30
              ? displayTarget.slice(0, 28) + '…'
              : displayTarget}
          </span>
        </div>

        {/* status row */}
        <div className="flex items-center gap-1.5">
          <StatusBadge value={scan.status} />
          {isRunning && runningTool && (
            <span className="text-xs font-mono text-amber-400 bg-amber-400/10 px-1.5 py-0.5 rounded truncate">
              {runningTool}
            </span>
          )}
        </div>

        {/* quick nav links */}
        <div className="flex gap-1 pt-0.5">
          {[
            { to: `/scan/${id}/graph`,  icon: <GitGraph size={11} />,     label: 'Graph'  },
            { to: `/scan/${id}/vulns`,  icon: <ShieldAlert size={11} />,  label: 'Vulns'  },
            { to: `/scan/${id}/report`, icon: <FileBarChart size={11} />, label: 'Report' },
          ].map(({ to, icon, label }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                `flex items-center gap-1 px-2 py-1 rounded text-xs transition-colors ${
                  isActive
                    ? 'bg-briar-accent text-black font-semibold'
                    : 'text-slate-500 hover:text-slate-300 hover:bg-briar-surface-2'
                }`
              }
            >
              {icon}
              {label}
            </NavLink>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── Sidebar ────────────────────────────────────────────────────────────────────

function Sidebar() {
  const base     = 'flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm transition-colors'
  const active   = 'bg-briar-accent text-black font-semibold'
  const inactive = 'text-slate-400 hover:text-slate-100 hover:bg-briar-surface-2'

  return (
    <aside className="w-56 bg-briar-surface border-r border-briar-border flex flex-col shrink-0">
      {/* Logo */}
      <div className="px-4 py-5 border-b border-briar-border">
        <div className="flex items-center gap-2.5">
          {/* Briar mark — thorned diamond */}
          <div className="w-7 h-7 rounded-lg bg-briar-accent flex items-center justify-center shrink-0">
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
              <path
                d="M7 1 L13 7 L7 13 L1 7 Z"
                fill="black"
                stroke="none"
              />
              <path
                d="M7 4 L10 7 L7 10 L4 7 Z"
                fill="#f59e0b"
              />
            </svg>
          </div>
          <div>
            <span className="font-bold text-slate-100 tracking-tight">Briar</span>
            <span className="text-slate-600 text-xs ml-1.5">v0.2</span>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 p-3 space-y-0.5">
        <NavLink to="/dashboard" className={({ isActive }) => `${base} ${isActive ? active : inactive}`}>
          <LayoutDashboard size={15} />
          Dashboard
        </NavLink>
        <NavLink to="/auth" className={({ isActive }) => `${base} ${isActive ? active : inactive}`}>
          <Key size={15} />
          Auth Sessions
        </NavLink>
        <NavLink to="/vulns" className={({ isActive }) => `${base} ${isActive ? active : inactive}`}>
          <ShieldAlert size={15} />
          Vulnerabilities
        </NavLink>
        <NavLink to="/tools" className={({ isActive }) => `${base} ${isActive ? active : inactive}`}>
          <Wrench size={15} />
          Tools
        </NavLink>
        <NavLink to="/schedules" className={({ isActive }) => `${base} ${isActive ? active : inactive}`}>
          <CalendarClock size={15} />
          Schedules
        </NavLink>

        {/* Divider */}
        <div className="border-t border-briar-border !my-3" />

        <p className="px-3 text-xs text-slate-600 uppercase tracking-wide pb-1 select-none">
          Reports
        </p>
        <NavLink to="/dashboard" className={`${base} ${inactive} opacity-50`}>
          <FileBarChart size={15} />
          Open scan → Report
        </NavLink>
      </nav>

      {/* Scan context panel — visible when inside a scan route */}
      <ScanContextPanel />

      {/* Footer */}
      <div className="p-3 border-t border-briar-border">
        <p className="text-xs text-slate-600">DAST Automation Platform</p>
      </div>
    </aside>
  )
}

// ── Layout ─────────────────────────────────────────────────────────────────────

function Layout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-full">
      <Sidebar />
      <main className="flex-1 overflow-auto">{children}</main>
    </div>
  )
}

// ── App root ───────────────────────────────────────────────────────────────────

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Suspense
          fallback={
            <div className="flex items-center justify-center h-screen text-slate-500 text-sm">
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
