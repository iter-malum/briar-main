import { useState, useEffect, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  RefreshCw, Plus, GitGraph, ShieldAlert, ExternalLink,
  StopCircle, Trash2, FileBarChart, ChevronDown, ChevronUp,
  AlertTriangle, Zap, Database,
} from 'lucide-react'
import {
  fetchScans, createScan, cancelScan, deleteScan,
  fetchAuthSessions, downloadHtmlReport, downloadJsonReport,
  fetchCacheStats,
} from '../api/client'
import type { CacheStats } from '../api/client'
import { StatusBadge } from '../components/StatusBadge'
import type { Scan, AuthSession } from '../types'

// ── Tool catalogue ─────────────────────────────────────────────────────────────

const TOOL_GROUPS: Record<string, { label: string; tools: string[]; color: string }> = {
  recon: {
    label: 'Recon',
    color: 'text-blue-400',
    tools: ['whatweb', 'katana', 'httpx', 'ffuf', 'gobuster', 'arjun', 'jsscanner', 'retirejs'],
  },
  dast: {
    label: 'DAST',
    color: 'text-yellow-400',
    tools: ['nuclei', 'zap', 'nikto', 'dalfox', 'inspector', 'playwright', 'xxe'],
  },
  logic: {
    label: 'Auth & Logic',
    color: 'text-purple-400',
    tools: ['bola', 'creds', 'bizlogic', 'cors', 'graphql', 'openapi'],
  },
  exploit: {
    label: 'Exploit (needs flag)',
    color: 'text-red-400',
    tools: ['sqlmap', 'tplmap', 'commix', 'jwt_tool'],
  },
}

const ALL_TOOLS = Object.values(TOOL_GROUPS).flatMap((g) => g.tools)

const PRESETS: Record<string, string[]> = {
  quick:   ['whatweb', 'katana', 'httpx', 'nuclei'],
  full:    ['whatweb', 'katana', 'httpx', 'ffuf', 'gobuster', 'arjun',
            'nuclei', 'zap', 'nikto', 'dalfox', 'inspector',
            'jsscanner', 'retirejs', 'cors', 'bola', 'creds', 'bizlogic', 'playwright'],
  api:     ['whatweb', 'katana', 'httpx', 'arjun',
            'jsscanner', 'graphql', 'openapi', 'cors', 'bola', 'jwt_tool'],
  juiceshop: ['whatweb', 'katana', 'httpx', 'ffuf', 'gobuster', 'arjun',
              'nuclei', 'dalfox', 'inspector', 'jsscanner',
              'bola', 'creds', 'bizlogic', 'playwright'],
  exploit: ALL_TOOLS,
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleString()
}

// ── New scan modal ─────────────────────────────────────────────────────────────

function NewScanModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient()
  const [url, setUrl] = useState('')
  const [tools, setTools] = useState<string[]>(PRESETS.quick)
  const [preset, setPreset] = useState<string>('quick')
  const [selectedSession, setSelectedSession] = useState('')
  const [secondSession, setSecondSession] = useState('')
  const [exploitEnabled, setExploitEnabled] = useState(false)
  const [useEndpointCache, setUseEndpointCache] = useState(false)
  const [cacheStats, setCacheStats] = useState<CacheStats | null>(null)
  const [cacheLoading, setCacheLoading] = useState(false)
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [error, setError] = useState('')
  const cacheTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Debounced cache check — fires 600ms after URL stops changing
  useEffect(() => {
    setCacheStats(null)
    setUseEndpointCache(false)
    if (!url || !url.startsWith('http')) return
    if (cacheTimerRef.current) clearTimeout(cacheTimerRef.current)
    cacheTimerRef.current = setTimeout(async () => {
      setCacheLoading(true)
      try {
        const stats = await fetchCacheStats(url)
        setCacheStats(stats)
        // Auto-enable cache if available and katana is selected
        if (stats.available && tools.includes('katana')) setUseEndpointCache(true)
      } catch {
        setCacheStats(null)
      } finally {
        setCacheLoading(false)
      }
    }, 600)
    return () => { if (cacheTimerRef.current) clearTimeout(cacheTimerRef.current) }
  }, [url])

  const { data: sessions } = useQuery({
    queryKey: ['auth-sessions'],
    queryFn: fetchAuthSessions,
  })

  const applyPreset = (p: string) => {
    setPreset(p)
    setTools(PRESETS[p] ?? [])
    if (p === 'exploit') setExploitEnabled(true)
  }

  const toggleTool = (t: string) => {
    setPreset('custom')
    setTools((prev) => (prev.includes(t) ? prev.filter((x) => x !== t) : [...prev, t]))
  }

  const mut = useMutation({
    mutationFn: () => createScan({
      target_url: url,
      tools,
      auth_session_id: selectedSession || null,
      exploit_enabled: exploitEnabled,
      use_endpoint_cache: useEndpointCache && tools.includes('katana'),
      second_auth_context: (secondSession && tools.includes('bola'))
        ? { session_id: secondSession, target_url: url }
        : null,
    }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['scans'] }); onClose() },
    onError: (e: Error) => setError(e.message),
  })

  const inputCls = 'w-full bg-briar-bg border border-briar-border rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-briar-accent'
  const hasBola = tools.includes('bola')

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 overflow-y-auto py-6">
      <div className="card w-full max-w-lg mx-4 space-y-4">
        <h2 className="text-lg font-semibold flex items-center gap-2">
          <Plus size={18} className="text-briar-accent" /> New Scan
        </h2>

        <div className="space-y-4">
          {/* Target URL */}
          <div>
            <label className="text-xs text-slate-400 mb-1 block">Target URL</label>
            <input
              type="url"
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className={inputCls}
            />
          </div>

          {/* Endpoint Cache / Warm Start */}
          {(cacheLoading || cacheStats) && (
            <div
              className={`rounded-lg px-3 py-2.5 flex items-start gap-3 text-xs transition-all ${
                cacheStats?.available
                  ? 'border border-emerald-500/30 bg-emerald-500/5'
                  : 'border border-slate-700 bg-slate-800/40'
              }`}
            >
              <Database
                size={14}
                className={`mt-0.5 shrink-0 ${cacheStats?.available ? 'text-emerald-400' : 'text-slate-500'}`}
              />
              <div className="flex-1 min-w-0">
                {cacheLoading && (
                  <p className="text-slate-400">Checking endpoint cache…</p>
                )}
                {!cacheLoading && cacheStats?.available && (
                  <>
                    <p className="text-emerald-300 font-medium">
                      Endpoint cache available — {cacheStats.endpoint_count} endpoints
                      {cacheStats.age_hours != null && (
                        <span className="text-emerald-500 font-normal">
                          {' '}· {cacheStats.age_hours < 1
                            ? 'less than 1h ago'
                            : `${Math.round(cacheStats.age_hours)}h ago`}
                        </span>
                      )}
                    </p>
                    <p className="text-slate-500 mt-0.5">
                      Skip katana crawl and start probe/DAST immediately using results from a previous scan.
                    </p>
                    <label className="flex items-center gap-2 mt-2 cursor-pointer">
                      <div
                        onClick={() => setUseEndpointCache((x) => !x)}
                        className={`w-8 h-4 rounded-full transition-colors flex items-center shrink-0 ${
                          useEndpointCache ? 'bg-emerald-500' : 'bg-briar-border'
                        }`}
                      >
                        <div className={`w-3 h-3 bg-white rounded-full shadow transition-transform mx-0.5 ${
                          useEndpointCache ? 'translate-x-4' : 'translate-x-0'
                        }`} />
                      </div>
                      <span className={useEndpointCache ? 'text-emerald-300' : 'text-slate-400'}>
                        {useEndpointCache ? 'Warm start ON — katana will be skipped' : 'Warm start OFF — run full crawl'}
                      </span>
                    </label>
                  </>
                )}
                {!cacheLoading && cacheStats && !cacheStats.available && (
                  <p className="text-slate-500">No cached endpoints for this target — full crawl will run.</p>
                )}
              </div>
            </div>
          )}

          {/* Auth session */}
          <div>
            <label className="text-xs text-slate-400 mb-1 block">Auth Session (optional)</label>
            <select
              value={selectedSession}
              onChange={e => setSelectedSession(e.target.value)}
              className={`${inputCls} bg-briar-bg`}
            >
              <option value="">— No authentication —</option>
              {sessions?.map((s: AuthSession) => (
                <option key={s.session_id} value={s.session_id}>
                  [{s.auth_type}] {s.target_url} ({s.session_id.slice(0, 8)})
                </option>
              ))}
            </select>
            {!sessions?.length && (
              <p className="text-xs text-slate-600 mt-1">
                No sessions. <a href="/auth" className="text-briar-accent hover:underline">Create one</a> for authenticated scanning.
              </p>
            )}
          </div>

          {/* Presets */}
          <div>
            <label className="text-xs text-slate-400 mb-2 block">Scan Preset</label>
            <div className="flex gap-2 mb-3 flex-wrap">
              {[
                { key: 'quick',   label: 'Quick',   hint: '~5 min' },
                { key: 'full',    label: 'Full',    hint: '~45 min' },
                { key: 'api',     label: 'API',     hint: 'REST/GraphQL' },
                { key: 'exploit', label: 'Exploit', hint: 'all tools' },
                { key: 'custom',  label: 'Custom',  hint: '' },
              ].map(({ key, label, hint }) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => applyPreset(key)}
                  className={`px-3 py-1 rounded-lg text-xs border transition-colors ${
                    preset === key
                      ? 'bg-briar-accent border-briar-accent text-white'
                      : 'border-briar-border text-slate-400 hover:border-slate-500'
                  }`}
                >
                  {label}
                  {hint && <span className="ml-1 opacity-60">{hint}</span>}
                </button>
              ))}
            </div>

            {/* Tool groups */}
            {Object.entries(TOOL_GROUPS).map(([gk, g]) => (
              <div key={gk} className="mb-3">
                <p className={`text-xs font-semibold mb-1 ${g.color}`}>{g.label}</p>
                <div className="flex flex-wrap gap-1.5">
                  {g.tools.map((t) => (
                    <button
                      key={t}
                      type="button"
                      onClick={() => toggleTool(t)}
                      className={`px-2.5 py-0.5 rounded text-xs border transition-colors ${
                        tools.includes(t)
                          ? 'bg-briar-accent/20 border-briar-accent text-briar-accent'
                          : 'border-briar-border text-slate-500 hover:border-slate-400 hover:text-slate-300'
                      }`}
                    >
                      {t}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>

          {/* Advanced options */}
          <div>
            <button
              type="button"
              onClick={() => setShowAdvanced((x) => !x)}
              className="flex items-center gap-1 text-xs text-slate-500 hover:text-slate-300"
            >
              {showAdvanced ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
              Advanced options
            </button>

            {showAdvanced && (
              <div className="mt-3 space-y-3 pl-3 border-l border-briar-border">
                {/* Exploit enabled */}
                <label className="flex items-center gap-3 cursor-pointer">
                  <div
                    onClick={() => setExploitEnabled((x) => !x)}
                    className={`w-9 h-5 rounded-full transition-colors flex items-center ${
                      exploitEnabled ? 'bg-red-500' : 'bg-briar-border'
                    }`}
                  >
                    <div className={`w-4 h-4 bg-white rounded-full shadow transition-transform mx-0.5 ${
                      exploitEnabled ? 'translate-x-4' : 'translate-x-0'
                    }`} />
                  </div>
                  <div>
                    <p className="text-xs text-slate-300 font-medium flex items-center gap-1">
                      <AlertTriangle size={11} className="text-red-400" />
                      Enable exploit mode
                    </p>
                    <p className="text-xs text-slate-600">
                      Allows sqlmap/tplmap/commix to attempt actual exploitation (safe targets only)
                    </p>
                  </div>
                </label>

                {/* Second auth context for BOLA */}
                {hasBola && sessions && sessions.length > 1 && (
                  <div>
                    <label className="text-xs text-slate-400 mb-1 block flex items-center gap-1">
                      <Zap size={11} className="text-purple-400" />
                      BOLA: Second User Session
                    </label>
                    <select
                      value={secondSession}
                      onChange={e => setSecondSession(e.target.value)}
                      className={`${inputCls} bg-briar-bg`}
                    >
                      <option value="">— Single-user test only —</option>
                      {sessions
                        .filter((s: AuthSession) => s.session_id !== selectedSession)
                        .map((s: AuthSession) => (
                          <option key={s.session_id} value={s.session_id}>
                            [{s.auth_type}] {s.target_url} ({s.session_id.slice(0, 8)})
                          </option>
                        ))}
                    </select>
                    <p className="text-xs text-slate-600 mt-1">
                      Used for cross-user BOLA testing — worker will compare resource access between both sessions.
                    </p>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {exploitEnabled && (
          <div className="rounded-lg border border-red-500/30 bg-red-500/5 px-3 py-2 text-xs text-red-400 flex items-start gap-2">
            <AlertTriangle size={14} className="mt-0.5 shrink-0" />
            Exploit mode is ON. Only use against targets you own or have written permission to test.
          </div>
        )}

        {error && <p className="text-red-400 text-sm">{error}</p>}

        <div className="flex justify-end gap-2 pt-2">
          <button onClick={onClose} className="btn-ghost">Cancel</button>
          <button
            onClick={() => mut.mutate()}
            disabled={!url || tools.length === 0 || mut.isPending}
            className="btn-primary"
          >
            {mut.isPending ? 'Starting…' : 'Start Scan'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Scan row ───────────────────────────────────────────────────────────────────

function ScanRow({ scan }: { scan: Scan }) {
  const qc = useQueryClient()
  const [reportLoading, setReportLoading] = useState(false)
  const completed = scan.steps.filter((s) => s.status === 'completed').length
  const total = scan.steps.length
  const pct = total ? Math.round((completed / total) * 100) : 0
  const runningStep = scan.steps.find((s) => s.status === 'running')

  const cancelMut = useMutation({
    mutationFn: () => cancelScan(scan.id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  })

  const deleteMut = useMutation({
    mutationFn: () => deleteScan(scan.id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
    onError: (e: Error) => alert(e.message),
  })

  const handleReport = async () => {
    setReportLoading(true)
    try { await downloadHtmlReport(scan.id) }
    catch (e: any) { alert(e.message) }
    finally { setReportLoading(false) }
  }

  return (
    <tr className="border-b border-briar-border hover:bg-white/[0.02] transition-colors">
      <td className="table-cell font-mono text-xs text-slate-500">{scan.id.slice(0, 8)}…</td>
      <td className="table-cell">
        <a
          href={scan.target_url}
          target="_blank"
          rel="noreferrer"
          className="text-briar-accent hover:underline flex items-center gap-1"
        >
          {scan.target_url}
          <ExternalLink size={12} />
        </a>
      </td>
      <td className="table-cell">
        <div className="flex items-center gap-2">
          <StatusBadge value={scan.status} />
          {scan.status === 'running' && runningStep && (
            <span className="text-xs font-mono text-emerald-400 bg-emerald-400/10 px-1.5 py-0.5 rounded">
              {runningStep.tool}
            </span>
          )}
        </div>
      </td>
      <td className="table-cell">
        <div className="flex items-center gap-2">
          <div className="w-20 h-1.5 bg-briar-border rounded-full overflow-hidden">
            <div
              className="h-full bg-briar-accent rounded-full transition-all"
              style={{ width: `${pct}%` }}
            />
          </div>
          <span className="text-xs text-slate-500">{completed}/{total}</span>
        </div>
      </td>
      <td className="table-cell text-slate-500 text-xs">{formatDate(scan.created_at)}</td>
      <td className="table-cell">
        <div className="flex items-center gap-1 flex-wrap">
          <Link to={`/scan/${scan.id}/graph`} className="btn-ghost py-1 px-2 flex items-center gap-1">
            <GitGraph size={14} /> Graph
          </Link>
          <Link to={`/scan/${scan.id}/vulns`} className="btn-ghost py-1 px-2 flex items-center gap-1">
            <ShieldAlert size={14} /> Vulns
          </Link>
          <Link to={`/scan/${scan.id}/report`} className="btn-ghost py-1 px-2 flex items-center gap-1 text-briar-accent">
            <FileBarChart size={14} /> Report
          </Link>
          {scan.status === 'completed' && (
            <button
              onClick={handleReport}
              disabled={reportLoading}
              className="btn-ghost py-1 px-2 flex items-center gap-1 text-xs"
              title="Download HTML report"
            >
              {reportLoading ? '…' : '↓ HTML'}
            </button>
          )}
          {(scan.status === 'running' || scan.status === 'pending') && (
            <button
              onClick={() => { if (confirm('Cancel this scan?')) cancelMut.mutate() }}
              disabled={cancelMut.isPending}
              className="flex items-center gap-1 px-2 py-1 rounded text-red-400 border border-red-500/30 hover:bg-red-500/10 text-xs transition-colors"
            >
              <StopCircle size={12} />
              {cancelMut.isPending ? '…' : 'Stop'}
            </button>
          )}
          {(scan.status === 'completed' || scan.status === 'failed') && (
            <button
              onClick={() => { if (confirm('Delete this scan and all its data?')) deleteMut.mutate() }}
              disabled={deleteMut.isPending}
              className="flex items-center gap-1 px-2 py-1 rounded text-slate-500 border border-slate-700 hover:text-red-400 hover:border-red-500/30 hover:bg-red-500/10 text-xs transition-colors"
            >
              <Trash2 size={12} />
              {deleteMut.isPending ? '…' : 'Delete'}
            </button>
          )}
        </div>
      </td>
    </tr>
  )
}

// ── Dashboard ──────────────────────────────────────────────────────────────────

const STAT_CARDS = [
  {
    label: 'Total scans',
    key: 'total' as const,
    icon: <GitGraph size={18} />,
    accent: 'rgba(124,111,255,0.18)',
    border: 'rgba(124,111,255,0.35)',
    text: '#a89fff',
  },
  {
    label: 'Running',
    key: 'running' as const,
    icon: <Zap size={18} />,
    accent: 'rgba(63,168,213,0.18)',
    border: 'rgba(63,168,213,0.35)',
    text: '#60c8f0',
  },
  {
    label: 'Completed',
    key: 'completed' as const,
    icon: <ShieldAlert size={18} />,
    accent: 'rgba(16,185,129,0.18)',
    border: 'rgba(16,185,129,0.35)',
    text: '#34d399',
  },
  {
    label: 'Failed',
    key: 'failed' as const,
    icon: <AlertTriangle size={18} />,
    accent: 'rgba(239,68,68,0.18)',
    border: 'rgba(239,68,68,0.28)',
    text: '#f87171',
  },
]

export default function Dashboard() {
  const [showModal, setShowModal] = useState(false)
  const qc = useQueryClient()

  const { data: scans, isLoading, isError } = useQuery({
    queryKey: ['scans'],
    queryFn: fetchScans,
    refetchInterval: 5000,
  })

  const counts = {
    total:     scans?.length ?? 0,
    running:   scans?.filter((s) => s.status === 'running').length   ?? 0,
    completed: scans?.filter((s) => s.status === 'completed').length ?? 0,
    failed:    scans?.filter((s) => s.status === 'failed').length    ?? 0,
  }

  return (
    <div
      className="min-h-screen"
      style={{
        background: [
          'radial-gradient(ellipse 60% 40% at 10% 0%, rgba(124,111,255,0.07) 0%, transparent 60%)',
          'radial-gradient(ellipse 50% 35% at 90% 100%, rgba(63,168,213,0.05) 0%, transparent 60%)',
        ].join(', '),
      }}
    >
      <div className="px-6 pt-8 pb-10 max-w-7xl mx-auto space-y-8">

        {/* ── Hero header ─────────────────────────────────────────────────── */}
        <div className="flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span
                className="text-xs font-mono tracking-widest uppercase px-2 py-0.5 rounded"
                style={{ background: 'rgba(124,111,255,0.15)', color: '#a89fff', border: '1px solid rgba(124,111,255,0.3)' }}
              >
                Briar DAST
              </span>
              <span
                className="text-xs font-mono tracking-widest uppercase px-2 py-0.5 rounded"
                style={{ background: 'rgba(16,185,129,0.12)', color: '#34d399', border: '1px solid rgba(16,185,129,0.25)' }}
              >
                ● Live
              </span>
            </div>
            <h1 className="text-3xl font-bold text-slate-100 tracking-tight">
              Scan Dashboard
            </h1>
            <p className="text-slate-500 text-sm mt-1">
              Automated penetration testing — {scans?.length ?? '…'} scan sessions
            </p>
          </div>
          <div className="flex gap-2 shrink-0 pt-1">
            <button
              onClick={() => qc.invalidateQueries({ queryKey: ['scans'] })}
              className="btn-ghost flex items-center gap-2 text-xs"
            >
              <RefreshCw size={13} /> Refresh
            </button>
            <button
              onClick={() => setShowModal(true)}
              className="btn-primary flex items-center gap-2"
            >
              <Plus size={14} /> New Scan
            </button>
          </div>
        </div>

        {/* ── Stat cards ──────────────────────────────────────────────────── */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {STAT_CARDS.map(({ label, key, icon, accent, border, text }) => (
            <div
              key={key}
              className="rounded-xl p-5 flex flex-col gap-3"
              style={{
                background: `linear-gradient(135deg, ${accent} 0%, rgba(0,0,0,0) 100%), #1c1a1a`,
                border: `1px solid ${border}`,
              }}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs text-slate-500 font-medium tracking-wide uppercase">{label}</span>
                <span style={{ color: text, opacity: 0.7 }}>{icon}</span>
              </div>
              <div className="text-4xl font-bold tracking-tight" style={{ color: text }}>
                {counts[key]}
              </div>
            </div>
          ))}
        </div>

        {/* ── Scan table ──────────────────────────────────────────────────── */}
        <div>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider">
              Recent Scans
            </h2>
            {counts.running > 0 && (
              <span
                className="text-xs px-2 py-0.5 rounded-full font-mono"
                style={{ background: 'rgba(63,168,213,0.12)', color: '#60c8f0', border: '1px solid rgba(63,168,213,0.25)' }}
              >
                {counts.running} running
              </span>
            )}
          </div>

          <div
            className="rounded-xl overflow-hidden"
            style={{ border: '1px solid rgba(124,111,255,0.2)', background: '#1c1a1a' }}
          >
            {isLoading && (
              <div className="p-12 text-center text-slate-600">
                <RefreshCw size={20} className="animate-spin mx-auto mb-3 opacity-40" />
                Loading scans…
              </div>
            )}
            {isError && (
              <div className="p-12 text-center text-red-400 text-sm">
                Failed to load scans. Is the UI service running?
              </div>
            )}
            {scans && scans.length === 0 && (
              <div className="p-16 text-center">
                <div
                  className="w-14 h-14 rounded-2xl flex items-center justify-center mx-auto mb-4"
                  style={{ background: 'rgba(124,111,255,0.1)', border: '1px solid rgba(124,111,255,0.2)' }}
                >
                  <ShieldAlert size={24} style={{ color: '#a89fff' }} />
                </div>
                <p className="text-slate-400 text-sm font-medium">No scans yet</p>
                <p className="text-slate-600 text-xs mt-1">Click "New Scan" to launch your first DAST assessment</p>
                <button
                  onClick={() => setShowModal(true)}
                  className="mt-5 btn-primary flex items-center gap-2 mx-auto"
                >
                  <Plus size={14} /> New Scan
                </button>
              </div>
            )}
            {scans && scans.length > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr style={{ borderBottom: '1px solid rgba(124,111,255,0.15)' }}>
                      <th className="table-header">ID</th>
                      <th className="table-header">Target</th>
                      <th className="table-header">Status</th>
                      <th className="table-header">Progress</th>
                      <th className="table-header">Created</th>
                      <th className="table-header">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scans.map((scan) => (
                      <ScanRow key={scan.id} scan={scan} />
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </div>

      {showModal && <NewScanModal onClose={() => setShowModal(false)} />}
    </div>
  )
}
