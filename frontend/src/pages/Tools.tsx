import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ChevronDown, ChevronRight, Save, Loader2, CheckCircle, Lock } from 'lucide-react'
import { fetchTools, updateToolConfig } from '../api/client'
import type { ToolDefinition, ToolParam } from '../types'

const GROUP_META: Record<string, { label: string; description: string; borderColor: string; badgeColor: string }> = {
  recon: {
    label: 'Reconnaissance & Discovery',
    description: 'Discover endpoints, map structure, fingerprint technologies',
    borderColor: 'border-blue-500/30',
    badgeColor: 'bg-blue-500/20 text-blue-300',
  },
  dast: {
    label: 'Dynamic Analysis (DAST)',
    description: 'Exploit vulnerabilities using discovered endpoints',
    borderColor: 'border-orange-500/30',
    badgeColor: 'bg-orange-500/20 text-orange-300',
  },
  smart: {
    label: 'Smart Orchestration',
    description: 'Intelligent tool chaining and CVE mapping',
    borderColor: 'border-purple-500/30',
    badgeColor: 'bg-purple-500/20 text-purple-300',
  },
}

function ParamField({ param, value, onChange }: {
  param: ToolParam
  value: any
  onChange: (v: any) => void
}) {
  const inputCls = 'bg-briar-bg border border-briar-border rounded-lg px-3 py-1.5 text-sm text-slate-100 focus:outline-none focus:border-briar-accent w-full font-mono'

  if (param.type === 'boolean') {
    return (
      <label className="flex items-center gap-2 cursor-pointer">
        <div
          onClick={() => onChange(!value)}
          className={`relative w-10 h-5 rounded-full transition-colors cursor-pointer ${value ? 'bg-briar-accent' : 'bg-briar-border'}`}
        >
          <div className={`absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform ${value ? 'translate-x-5' : 'translate-x-0.5'}`} />
        </div>
        <span className="text-xs text-slate-400">{value ? 'Enabled' : 'Disabled'}</span>
      </label>
    )
  }

  if (param.type === 'select') {
    return (
      <select
        value={value}
        onChange={e => onChange(e.target.value)}
        className={`${inputCls} bg-briar-bg`}
      >
        {param.options?.map(opt => (
          <option key={opt} value={opt}>{opt || '— auto detect —'}</option>
        ))}
      </select>
    )
  }

  if (param.type === 'number') {
    return (
      <input
        type="number"
        value={value}
        min={param.min}
        max={param.max}
        onChange={e => onChange(Number(e.target.value))}
        className={inputCls}
      />
    )
  }

  if (param.type === 'textarea') {
    return (
      <textarea
        value={value}
        rows={3}
        onChange={e => onChange(e.target.value)}
        className={`${inputCls} resize-y`}
      />
    )
  }

  return (
    <input
      type="text"
      value={value}
      onChange={e => onChange(e.target.value)}
      className={inputCls}
    />
  )
}

function ToolCard({ tool }: { tool: ToolDefinition }) {
  const qc = useQueryClient()
  const [expanded, setExpanded] = useState(false)
  const [values, setValues] = useState<Record<string, any>>(() =>
    Object.fromEntries(tool.params.map(p => [p.key, p.value]))
  )
  const [saved, setSaved] = useState(false)

  const saveMut = useMutation({
    mutationFn: () => updateToolConfig(tool.id, values),
    onSuccess: () => {
      setSaved(true)
      qc.invalidateQueries({ queryKey: ['tools'] })
      setTimeout(() => setSaved(false), 2000)
    },
  })

  const hasChanges = tool.params.some(p => String(values[p.key]) !== String(p.value))
  const groupMeta = GROUP_META[tool.group]

  return (
    <div className={`card border ${tool.available ? groupMeta.borderColor : 'border-briar-border opacity-60'} space-y-0 p-0 overflow-hidden`}>
      {/* Card header */}
      <div
        className="flex items-center gap-3 p-4 cursor-pointer hover:bg-white/[0.02] transition-colors"
        onClick={() => tool.available && setExpanded(x => !x)}
      >
        <div className="text-2xl w-10 h-10 flex items-center justify-center bg-briar-bg rounded-lg shrink-0">
          {tool.emoji}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-semibold text-slate-100 text-sm">{tool.name}</span>
            {!tool.available && (
              <span className="flex items-center gap-1 text-xs text-slate-500 bg-slate-700/50 px-2 py-0.5 rounded-full">
                <Lock size={10} /> Coming Soon
              </span>
            )}
          </div>
          <p className="text-xs text-slate-500 mt-0.5 line-clamp-2">{tool.description}</p>
        </div>
        {tool.available && tool.params.length > 0 && (
          <div className="shrink-0 text-slate-500">
            {expanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
          </div>
        )}
      </div>

      {/* Expanded params */}
      {expanded && tool.available && (
        <div className="border-t border-briar-border p-4 space-y-4 bg-briar-bg/30">
          {tool.params.map(param => (
            <div key={param.key}>
              <div className="flex items-center justify-between mb-1">
                <label className="text-xs font-medium text-slate-300">{param.label}</label>
                {param.type !== 'boolean' && (
                  <span className="text-xs text-slate-600 font-mono">default: {String(param.default) || '(empty)'}</span>
                )}
              </div>
              <ParamField
                param={param}
                value={values[param.key]}
                onChange={v => setValues(prev => ({ ...prev, [param.key]: v }))}
              />
              <p className="text-xs text-slate-600 mt-1 leading-relaxed">{param.description}</p>
            </div>
          ))}

          <div className="flex justify-end pt-2">
            <button
              onClick={() => saveMut.mutate()}
              disabled={saveMut.isPending || !hasChanges}
              className="btn-primary flex items-center gap-2 py-1.5 px-4 text-sm disabled:opacity-50"
            >
              {saveMut.isPending
                ? <><Loader2 size={14} className="animate-spin" /> Saving…</>
                : saved
                ? <><CheckCircle size={14} /> Saved!</>
                : <><Save size={14} /> Save Config</>
              }
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

function GroupSection({ groupId, tools }: { groupId: string; tools: ToolDefinition[] }) {
  const meta = GROUP_META[groupId]
  if (!meta || tools.length === 0) return null

  const available = tools.filter(t => t.available).length
  const total = tools.length

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3">
        <div>
          <h2 className="text-lg font-bold text-slate-100">{meta.label}</h2>
          <p className="text-slate-500 text-xs mt-0.5">{meta.description}</p>
        </div>
        <div className="ml-auto flex items-center gap-2">
          <span className={`text-xs px-2 py-0.5 rounded-full ${meta.badgeColor}`}>
            {available}/{total} available
          </span>
        </div>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        {tools.map(tool => <ToolCard key={tool.id} tool={tool} />)}
      </div>
    </div>
  )
}

export default function Tools() {
  const { data: tools, isLoading, isError } = useQuery({
    queryKey: ['tools'],
    queryFn: fetchTools,
  })

  const byGroup: Record<string, ToolDefinition[]> = {}
  for (const tool of tools ?? []) {
    if (!byGroup[tool.group]) byGroup[tool.group] = []
    byGroup[tool.group].push(tool)
  }

  const totalAvailable = (tools ?? []).filter(t => t.available).length
  const totalTools = (tools ?? []).length

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Tools</h1>
          <p className="text-slate-400 text-sm mt-1">
            Configure all scanner tools — {totalAvailable} active, {totalTools - totalAvailable} planned
          </p>
        </div>
      </div>

      {/* Info */}
      <div className="rounded-lg border border-briar-accent/30 bg-briar-accent/5 p-4 text-xs text-slate-400 leading-relaxed">
        <span className="text-briar-accent font-medium">How tool config works: </span>
        Click any tool to expand its settings. Changes are applied to all future scans.
        Tools marked <span className="text-slate-300">Coming Soon</span> are planned for future milestones and will be available after the next update.
      </div>

      {isLoading && <div className="text-center text-slate-500 py-16">Loading tools…</div>}
      {isError && <div className="text-center text-red-400 py-16">Failed to load tools. Is the orchestrator running?</div>}

      {tools && (
        <div className="space-y-10">
          {['recon', 'dast', 'smart'].map(groupId => (
            <GroupSection
              key={groupId}
              groupId={groupId}
              tools={byGroup[groupId] ?? []}
            />
          ))}
        </div>
      )}
    </div>
  )
}
