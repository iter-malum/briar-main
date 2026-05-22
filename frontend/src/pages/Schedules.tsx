import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, Play, Pencil, Check, Clock, ToggleLeft, ToggleRight, ChevronDown, ChevronUp, TrendingUp, TrendingDown, Minus } from 'lucide-react'
import {
  fetchSchedules,
  createSchedule,
  updateSchedule,
  deleteSchedule,
  runScheduleNow,
  fetchScheduleDiff,
  fetchAuthSessions,
  fetchTools,
} from '../api/client'
import type { Schedule } from '../types'
import type { ScanDiff } from '../api/client'

const CRON_PRESETS = [
  { label: 'Every hour',    value: '@hourly' },
  { label: 'Every day',     value: '@daily' },
  { label: 'Every week',    value: '@weekly' },
  { label: 'Every month',   value: '@monthly' },
  { label: 'Every 6 hours', value: '0 */6 * * *' },
  { label: 'Custom…',       value: '' },
]

function fmtDate(s: string | null) {
  if (!s) return '—'
  return new Date(s).toLocaleString()
}

function Badge({ on }: { on: boolean }) {
  return on
    ? <span className="px-2 py-0.5 text-xs rounded-full bg-emerald-900/40 text-emerald-400 border border-emerald-800">enabled</span>
    : <span className="px-2 py-0.5 text-xs rounded-full bg-slate-700/50 text-slate-500 border border-slate-700">disabled</span>
}

interface FormState {
  label: string
  target_url: string
  tools: string[]
  auth_session_id: string
  cron_preset: string
  cron_custom: string
}

const EMPTY_FORM: FormState = {
  label: '',
  target_url: '',
  tools: [],
  auth_session_id: '',
  cron_preset: '@daily',
  cron_custom: '',
}

function ScheduleForm({
  initial,
  allTools,
  authSessions,
  onSave,
  onCancel,
  loading,
}: {
  initial: FormState
  allTools: string[]
  authSessions: { session_id: string; target_url: string }[]
  onSave: (f: FormState) => void
  onCancel: () => void
  loading: boolean
}) {
  const [f, setF] = useState<FormState>(initial)

  const cron = f.cron_preset === '' ? f.cron_custom : f.cron_preset

  function toggleTool(tool: string) {
    setF(prev => ({
      ...prev,
      tools: prev.tools.includes(tool) ? prev.tools.filter(t => t !== tool) : [...prev.tools, tool],
    }))
  }

  return (
    <div className="bg-briar-surface border border-briar-border rounded-xl p-5 space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-xs text-slate-400 mb-1">Label (optional)</label>
          <input
            className="w-full bg-briar-bg border border-briar-border rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-briar-accent"
            value={f.label}
            onChange={e => setF(p => ({ ...p, label: e.target.value }))}
            placeholder="e.g. Nightly scan — staging"
          />
        </div>
        <div>
          <label className="block text-xs text-slate-400 mb-1">Target URL *</label>
          <input
            className="w-full bg-briar-bg border border-briar-border rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-briar-accent"
            value={f.target_url}
            onChange={e => setF(p => ({ ...p, target_url: e.target.value }))}
            placeholder="https://example.com"
          />
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-xs text-slate-400 mb-1">Schedule</label>
          <select
            className="w-full bg-briar-bg border border-briar-border rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-briar-accent"
            value={f.cron_preset}
            onChange={e => setF(p => ({ ...p, cron_preset: e.target.value }))}
          >
            {CRON_PRESETS.map(p => (
              <option key={p.value} value={p.value}>{p.label}</option>
            ))}
          </select>
          {f.cron_preset === '' && (
            <input
              className="mt-2 w-full bg-briar-bg border border-briar-border rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-briar-accent font-mono"
              value={f.cron_custom}
              onChange={e => setF(p => ({ ...p, cron_custom: e.target.value }))}
              placeholder="*/30 * * * *"
            />
          )}
          <p className="mt-1 text-xs text-slate-600 font-mono">{cron || '—'}</p>
        </div>

        <div>
          <label className="block text-xs text-slate-400 mb-1">Auth session (optional)</label>
          <select
            className="w-full bg-briar-bg border border-briar-border rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-briar-accent"
            value={f.auth_session_id}
            onChange={e => setF(p => ({ ...p, auth_session_id: e.target.value }))}
          >
            <option value="">— none —</option>
            {authSessions.map(s => (
              <option key={s.session_id} value={s.session_id}>{s.target_url} ({s.session_id.slice(0, 8)})</option>
            ))}
          </select>
        </div>
      </div>

      <div>
        <label className="block text-xs text-slate-400 mb-2">Tools *</label>
        <div className="flex flex-wrap gap-2">
          {allTools.map(tool => (
            <button
              key={tool}
              type="button"
              onClick={() => toggleTool(tool)}
              className={`px-3 py-1 text-xs rounded-full border transition-colors ${
                f.tools.includes(tool)
                  ? 'bg-briar-accent/20 border-briar-accent text-briar-accent'
                  : 'bg-briar-bg border-briar-border text-slate-400 hover:border-slate-500'
              }`}
            >
              {tool}
            </button>
          ))}
        </div>
      </div>

      <div className="flex gap-2 justify-end pt-2">
        <button
          onClick={onCancel}
          className="px-4 py-1.5 text-sm rounded-lg border border-briar-border text-slate-400 hover:text-slate-100 hover:border-slate-500 transition-colors"
        >
          Cancel
        </button>
        <button
          onClick={() => onSave({ ...f, cron_custom: cron })}
          disabled={loading || !f.target_url || f.tools.length === 0 || !cron}
          className="px-4 py-1.5 text-sm rounded-lg bg-briar-accent text-white hover:bg-briar-accent/80 disabled:opacity-40 transition-colors flex items-center gap-2"
        >
          {loading ? <span className="animate-spin text-xs">⟳</span> : <Check size={14} />}
          Save
        </button>
      </div>
    </div>
  )
}

function DiffPanel({ scheduleId }: { scheduleId: string }) {
  const { data: diff, isLoading, isError, error } = useQuery<ScanDiff, Error>({
    queryKey: ['schedule-diff', scheduleId],
    queryFn: () => fetchScheduleDiff(scheduleId),
    staleTime: 60_000,
  })

  if (isLoading) return <p className="text-xs text-slate-500 py-2">Loading diff…</p>
  if (isError) return <p className="text-xs text-red-400 py-2">{(error as Error).message}</p>
  if (!diff) return null

  const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']

  function countBySev(vulns: ScanDiff['new']) {
    const m: Record<string, number> = {}
    for (const v of vulns) m[v.severity] = (m[v.severity] ?? 0) + 1
    return m
  }

  function SevPills({ vulns }: { vulns: ScanDiff['new'] }) {
    const counts = countBySev(vulns)
    const SEV_COLOR: Record<string, string> = {
      critical: 'text-red-400 bg-red-900/20',
      high:     'text-orange-400 bg-orange-900/20',
      medium:   'text-yellow-400 bg-yellow-900/20',
      low:      'text-blue-400 bg-blue-900/20',
      info:     'text-slate-400 bg-slate-700/30',
    }
    return (
      <div className="flex flex-wrap gap-1 mt-1">
        {SEV_ORDER.filter(s => counts[s]).map(s => (
          <span key={s} className={`px-1.5 py-0.5 text-xs rounded font-medium ${SEV_COLOR[s]}`}>
            {s[0].toUpperCase()} ×{counts[s]}
          </span>
        ))}
      </div>
    )
  }

  return (
    <div className="mt-3 pt-3 border-t border-briar-border space-y-3">
      <p className="text-xs text-slate-500">
        Diff: <span className="font-mono text-slate-400">{diff.scan_id.slice(0, 8)}</span>
        {' '}vs <span className="font-mono text-slate-400">{diff.compare_to.slice(0, 8)}</span>
        {' '}· {diff.scan_target}
      </p>

      <div className="grid grid-cols-3 gap-3">
        {/* New */}
        <div className="bg-red-950/20 border border-red-900/30 rounded-lg p-3">
          <div className="flex items-center gap-1.5 mb-1">
            <TrendingUp size={13} className="text-red-400" />
            <span className="text-xs font-medium text-red-400">New vulnerabilities</span>
            <span className="ml-auto text-sm font-bold text-red-300">{diff.summary.new}</span>
          </div>
          {diff.new.length > 0 && <SevPills vulns={diff.new} />}
        </div>

        {/* Fixed */}
        <div className="bg-emerald-950/20 border border-emerald-900/30 rounded-lg p-3">
          <div className="flex items-center gap-1.5 mb-1">
            <TrendingDown size={13} className="text-emerald-400" />
            <span className="text-xs font-medium text-emerald-400">Fixed</span>
            <span className="ml-auto text-sm font-bold text-emerald-300">{diff.summary.fixed}</span>
          </div>
          {diff.fixed.length > 0 && <SevPills vulns={diff.fixed} />}
        </div>

        {/* Persisted */}
        <div className="bg-slate-800/40 border border-slate-700/50 rounded-lg p-3">
          <div className="flex items-center gap-1.5 mb-1">
            <Minus size={13} className="text-slate-400" />
            <span className="text-xs font-medium text-slate-400">Persisted</span>
            <span className="ml-auto text-sm font-bold text-slate-300">{diff.summary.persisted}</span>
          </div>
          {diff.persisted.length > 0 && <SevPills vulns={diff.persisted} />}
        </div>
      </div>

      {diff.new.length > 0 && (
        <div className="space-y-1">
          <p className="text-xs text-slate-500 font-medium">New findings:</p>
          {diff.new.slice(0, 5).map(v => (
            <div key={v.id} className="flex items-start gap-2 text-xs">
              <span className={`mt-0.5 shrink-0 px-1 rounded text-[10px] font-medium ${
                v.severity === 'critical' ? 'bg-red-900/40 text-red-400' :
                v.severity === 'high'     ? 'bg-orange-900/40 text-orange-400' :
                v.severity === 'medium'   ? 'bg-yellow-900/40 text-yellow-400' :
                                            'bg-slate-700 text-slate-400'
              }`}>{v.severity[0].toUpperCase()}</span>
              <span className="text-slate-300 truncate">{v.vulnerability_type ?? v.tool}</span>
              {v.url && <span className="text-slate-600 truncate max-w-[200px]">{v.url}</span>}
            </div>
          ))}
          {diff.new.length > 5 && (
            <p className="text-xs text-slate-600">…and {diff.new.length - 5} more</p>
          )}
        </div>
      )}
    </div>
  )
}

function ScheduleRow({
  schedule,
  allTools,
  authSessions,
  onDelete,
  onToggle,
  onRunNow,
  onEdit,
}: {
  schedule: Schedule
  allTools: string[]
  authSessions: { session_id: string; target_url: string }[]
  onDelete: () => void
  onToggle: () => void
  onRunNow: () => void
  onEdit: () => void
}) {
  const [showDiff, setShowDiff] = useState(false)
  const hasDiff = !!(schedule.last_scan_id && schedule.prev_scan_id)

  return (
    <div className={`bg-briar-surface border rounded-xl p-4 transition-opacity ${schedule.enabled ? 'border-briar-border' : 'border-briar-border opacity-60'}`}>
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <Badge on={schedule.enabled} />
            {schedule.label && (
              <span className="text-sm font-medium text-slate-100">{schedule.label}</span>
            )}
            <span className="text-xs font-mono text-briar-accent bg-briar-accent/10 px-2 py-0.5 rounded">
              {schedule.cron_expression}
            </span>
          </div>
          <p className="text-sm text-slate-300 truncate">{schedule.target_url}</p>
          <div className="mt-1.5 flex flex-wrap gap-1">
            {schedule.tools.map(t => (
              <span key={t} className="px-1.5 py-0.5 text-xs bg-slate-800 text-slate-400 rounded">{t}</span>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-1 shrink-0">
          {hasDiff && (
            <button
              onClick={() => setShowDiff(v => !v)}
              title="Show diff vs previous run"
              className={`p-1.5 rounded-lg transition-colors text-xs flex items-center gap-1 px-2 ${
                showDiff
                  ? 'bg-briar-accent/20 text-briar-accent border border-briar-accent/30'
                  : 'text-slate-400 hover:text-briar-accent hover:bg-briar-accent/10'
              }`}
            >
              {showDiff ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
              Diff
            </button>
          )}
          <button
            onClick={onRunNow}
            title="Run now"
            className="p-1.5 rounded-lg text-slate-400 hover:text-emerald-400 hover:bg-emerald-900/20 transition-colors"
          >
            <Play size={14} />
          </button>
          <button
            onClick={onEdit}
            title="Edit"
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-briar-bg transition-colors"
          >
            <Pencil size={14} />
          </button>
          <button
            onClick={onToggle}
            title={schedule.enabled ? 'Disable' : 'Enable'}
            className="p-1.5 rounded-lg text-slate-400 hover:text-yellow-400 hover:bg-yellow-900/20 transition-colors"
          >
            {schedule.enabled ? <ToggleRight size={14} /> : <ToggleLeft size={14} />}
          </button>
          <button
            onClick={onDelete}
            title="Delete"
            className="p-1.5 rounded-lg text-slate-400 hover:text-red-400 hover:bg-red-900/20 transition-colors"
          >
            <Trash2 size={14} />
          </button>
        </div>
      </div>

      <div className="mt-3 grid grid-cols-3 gap-3 text-xs text-slate-500">
        <div>
          <Clock size={11} className="inline mr-1" />
          Next: <span className="text-slate-300">{fmtDate(schedule.next_run_at)}</span>
        </div>
        <div>
          Last run: <span className="text-slate-300">{fmtDate(schedule.last_run_at)}</span>
        </div>
        <div>
          Runs: <span className="text-slate-300">{schedule.run_count}</span>
          {schedule.last_scan_id && (
            <> · last scan <span className="font-mono text-slate-400">{schedule.last_scan_id.slice(0, 8)}</span></>
          )}
        </div>
      </div>

      {showDiff && hasDiff && <DiffPanel scheduleId={schedule.id} />}
    </div>
  )
}

export default function Schedules() {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [editId, setEditId] = useState<string | null>(null)
  const [toast, setToast] = useState<string | null>(null)

  const { data: schedules = [], isLoading } = useQuery({
    queryKey: ['schedules'],
    queryFn: fetchSchedules,
    refetchInterval: 30_000,
  })

  const { data: authSessions = [] } = useQuery({
    queryKey: ['auth-sessions'],
    queryFn: fetchAuthSessions,
  })

  const { data: toolDefs = [] } = useQuery({
    queryKey: ['tools'],
    queryFn: fetchTools,
  })
  const allToolNames = toolDefs.map(t => t.id)

  function showToast(msg: string) {
    setToast(msg)
    setTimeout(() => setToast(null), 3000)
  }

  const createMut = useMutation({
    mutationFn: createSchedule,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['schedules'] })
      setShowCreate(false)
      showToast('Schedule created')
    },
    onError: (e: Error) => showToast(`Error: ${e.message}`),
  })

  const updateMut = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: Parameters<typeof updateSchedule>[1] }) =>
      updateSchedule(id, payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['schedules'] })
      setEditId(null)
      showToast('Schedule updated')
    },
    onError: (e: Error) => showToast(`Error: ${e.message}`),
  })

  const deleteMut = useMutation({
    mutationFn: deleteSchedule,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['schedules'] })
      showToast('Schedule deleted')
    },
    onError: (e: Error) => showToast(`Error: ${e.message}`),
  })

  const runNowMut = useMutation({
    mutationFn: runScheduleNow,
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ['schedules'] })
      showToast(`Scan started: ${data.scan_id.slice(0, 8)}`)
    },
    onError: (e: Error) => showToast(`Error: ${e.message}`),
  })

  function handleCreate(f: FormState) {
    const cron = f.cron_preset === '' ? f.cron_custom : f.cron_preset
    createMut.mutate({
      label: f.label || undefined,
      target_url: f.target_url,
      tools: f.tools,
      auth_session_id: f.auth_session_id || null,
      cron_expression: cron,
    })
  }

  function handleEdit(id: string, f: FormState) {
    const cron = f.cron_preset === '' ? f.cron_custom : f.cron_preset
    updateMut.mutate({
      id,
      payload: {
        label: f.label || undefined,
        tools: f.tools,
        auth_session_id: f.auth_session_id || null,
        cron_expression: cron,
      },
    })
  }

  function scheduleToForm(s: Schedule): FormState {
    const preset = CRON_PRESETS.find(p => p.value === s.cron_expression && p.value !== '')
    return {
      label: s.label ?? '',
      target_url: s.target_url,
      tools: s.tools,
      auth_session_id: s.auth_session_id ?? '',
      cron_preset: preset ? preset.value : '',
      cron_custom: preset ? '' : s.cron_expression,
    }
  }

  const sessions = authSessions.map(s => ({ session_id: s.session_id, target_url: s.target_url }))

  return (
    <div className="p-6 space-y-6">
      {/* Toast */}
      {toast && (
        <div className="fixed top-4 right-4 z-50 bg-briar-surface border border-briar-border rounded-lg px-4 py-2 text-sm text-slate-100 shadow-xl">
          {toast}
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">Scheduled Scans</h1>
          <p className="text-sm text-slate-500 mt-0.5">Automatically run scans on a cron schedule</p>
        </div>
        <button
          onClick={() => { setShowCreate(true); setEditId(null) }}
          className="flex items-center gap-2 px-4 py-2 bg-briar-accent text-white rounded-lg text-sm hover:bg-briar-accent/80 transition-colors"
        >
          <Plus size={14} /> New Schedule
        </button>
      </div>

      {/* Create form */}
      {showCreate && (
        <ScheduleForm
          initial={EMPTY_FORM}
          allTools={allToolNames}
          authSessions={sessions}
          onSave={handleCreate}
          onCancel={() => setShowCreate(false)}
          loading={createMut.isPending}
        />
      )}

      {/* List */}
      {isLoading ? (
        <div className="text-slate-500 text-sm">Loading…</div>
      ) : schedules.length === 0 ? (
        <div className="text-center py-16 text-slate-600">
          <Clock size={32} className="mx-auto mb-3 opacity-40" />
          <p className="text-sm">No schedules yet. Click "New Schedule" to create one.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {schedules.map(s =>
            editId === s.id ? (
              <ScheduleForm
                key={s.id}
                initial={scheduleToForm(s)}
                allTools={allToolNames}
                authSessions={sessions}
                onSave={f => handleEdit(s.id, f)}
                onCancel={() => setEditId(null)}
                loading={updateMut.isPending}
              />
            ) : (
              <ScheduleRow
                key={s.id}
                schedule={s}
                allTools={allToolNames}
                authSessions={sessions}
                onDelete={() => {
                  if (confirm(`Delete schedule "${s.label || s.target_url}"?`)) deleteMut.mutate(s.id)
                }}
                onToggle={() => updateMut.mutate({ id: s.id, payload: { enabled: !s.enabled } })}
                onRunNow={() => runNowMut.mutate(s.id)}
                onEdit={() => { setEditId(s.id); setShowCreate(false) }}
              />
            )
          )}
        </div>
      )}
    </div>
  )
}
