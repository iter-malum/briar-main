import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { RefreshCw, Plus, GitGraph, ShieldAlert, ExternalLink, StopCircle } from 'lucide-react'
import { fetchScans, createScan, cancelScan } from '../api/client'
import { StatusBadge } from '../components/StatusBadge'
import type { Scan } from '../types'

const AVAILABLE_TOOLS = ['katana', 'httpx', 'nuclei', 'ffuf', 'zap']

function formatDate(iso: string) {
  return new Date(iso).toLocaleString()
}

function NewScanModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient()
  const [url, setUrl] = useState('')
  const [tools, setTools] = useState<string[]>(['katana', 'nuclei'])
  const [token, setToken] = useState('')
  const [error, setError] = useState('')

  const mut = useMutation({
    mutationFn: () => createScan({ target_url: url, tools }, token),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scans'] })
      onClose()
    },
    onError: (e: Error) => setError(e.message),
  })

  const toggleTool = (t: string) =>
    setTools((prev) => (prev.includes(t) ? prev.filter((x) => x !== t) : [...prev, t]))

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="card w-full max-w-md mx-4 space-y-4">
        <h2 className="text-lg font-semibold">New Scan</h2>

        <div className="space-y-3">
          <div>
            <label className="text-xs text-slate-400 mb-1 block">Target URL</label>
            <input
              type="url"
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="w-full bg-briar-bg border border-briar-border rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-briar-accent"
            />
          </div>

          <div>
            <label className="text-xs text-slate-400 mb-1 block">JWT Token (for gateway auth)</label>
            <input
              type="text"
              placeholder="eyJhbG..."
              value={token}
              onChange={(e) => setToken(e.target.value)}
              className="w-full bg-briar-bg border border-briar-border rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-briar-accent font-mono"
            />
          </div>

          <div>
            <label className="text-xs text-slate-400 mb-2 block">Tools</label>
            <div className="flex flex-wrap gap-2">
              {AVAILABLE_TOOLS.map((t) => (
                <button
                  key={t}
                  type="button"
                  onClick={() => toggleTool(t)}
                  className={`px-3 py-1 rounded-lg text-sm border transition-colors ${
                    tools.includes(t)
                      ? 'bg-briar-accent border-briar-accent text-white'
                      : 'border-briar-border text-slate-400 hover:border-slate-500'
                  }`}
                >
                  {t}
                </button>
              ))}
            </div>
          </div>
        </div>

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

function ScanRow({ scan }: { scan: Scan }) {
  const qc = useQueryClient()
  const completed = scan.steps.filter((s) => s.status === 'completed').length
  const total = scan.steps.length
  const pct = total ? Math.round((completed / total) * 100) : 0
  const runningStep = scan.steps.find((s) => s.status === 'running')

  const cancelMut = useMutation({
    mutationFn: () => cancelScan(scan.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scans'] })
    },
  })

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
          <span className="text-xs text-slate-500">{pct}%</span>
        </div>
      </td>
      <td className="table-cell text-slate-500 text-xs">{formatDate(scan.created_at)}</td>
      <td className="table-cell">
        <div className="flex items-center gap-1">
          <Link to={`/scan/${scan.id}/graph`} className="btn-ghost py-1 px-2 flex items-center gap-1">
            <GitGraph size={14} /> Graph
          </Link>
          <Link to={`/scan/${scan.id}/vulns`} className="btn-ghost py-1 px-2 flex items-center gap-1">
            <ShieldAlert size={14} /> Vulns
          </Link>
          {scan.status === 'running' && (
            <button
              onClick={() => {
                if (confirm('Cancel this scan?')) cancelMut.mutate()
              }}
              disabled={cancelMut.isPending}
              className="flex items-center gap-1 px-2 py-1 rounded text-red-400 border border-red-500/30 hover:bg-red-500/10 text-xs transition-colors"
              title="Stop scan"
            >
              <StopCircle size={12} />
              {cancelMut.isPending ? '…' : 'Stop'}
            </button>
          )}
        </div>
      </td>
    </tr>
  )
}

export default function Dashboard() {
  const [showModal, setShowModal] = useState(false)
  const qc = useQueryClient()

  const { data: scans, isLoading, isError } = useQuery({
    queryKey: ['scans'],
    queryFn: fetchScans,
    refetchInterval: 5000,
  })

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Dashboard</h1>
          <p className="text-slate-400 text-sm mt-1">Active DAST scan sessions</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => qc.invalidateQueries({ queryKey: ['scans'] })}
            className="btn-ghost flex items-center gap-2"
          >
            <RefreshCw size={14} /> Refresh
          </button>
          <button onClick={() => setShowModal(true)} className="btn-primary flex items-center gap-2">
            <Plus size={14} /> New Scan
          </button>
        </div>
      </div>

      {/* Stats */}
      {scans && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {[
            { label: 'Total', value: scans.length, color: 'text-slate-100' },
            { label: 'Running', value: scans.filter((s) => s.status === 'running').length, color: 'text-blue-400' },
            { label: 'Completed', value: scans.filter((s) => s.status === 'completed').length, color: 'text-emerald-400' },
            { label: 'Failed', value: scans.filter((s) => s.status === 'failed').length, color: 'text-red-400' },
          ].map(({ label, value, color }) => (
            <div key={label} className="card text-center">
              <div className={`text-3xl font-bold ${color}`}>{value}</div>
              <div className="text-slate-400 text-sm mt-1">{label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Table */}
      <div className="card p-0 overflow-hidden">
        {isLoading && (
          <div className="p-8 text-center text-slate-500">Loading scans…</div>
        )}
        {isError && (
          <div className="p-8 text-center text-red-400">Failed to load scans. Is the UI service running?</div>
        )}
        {scans && scans.length === 0 && (
          <div className="p-8 text-center text-slate-500">No scans yet. Click "New Scan" to get started.</div>
        )}
        {scans && scans.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="border-b border-briar-border">
                <tr>
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

      {showModal && <NewScanModal onClose={() => setShowModal(false)} />}
    </div>
  )
}
