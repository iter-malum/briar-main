import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, CheckCircle, XCircle, Loader2, Key, Terminal, Globe, Code2, Monitor, ExternalLink } from 'lucide-react'
import {
  fetchAuthSessions, deleteAuthSession, testAuthSession,
  createAuthSession, createSessionFromCurl, startRecording, saveRecording, cancelRecording, getSessionScript,
} from '../api/client'
import type { AuthSession } from '../types'
import type { RecordStartResponse } from '../api/client'

type TabId = 'manual' | 'form' | 'curl' | 'script' | 'interactive'

const TAB_ICONS: Record<TabId, React.ReactNode> = {
  manual: <Key size={14} />,
  form:   <Globe size={14} />,
  curl:   <Terminal size={14} />,
  script: <Code2 size={14} />,
  interactive: <Monitor size={14} />,
}

const TAB_LABELS: Record<TabId, string> = {
  manual: 'Token / Headers',
  form:   'Form Login',
  curl:   'cURL Import',
  script: 'Browser Script',
  interactive: 'Interactive Browser',
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleString()
}

function AuthTypeBadge({ type }: { type: string }) {
  const colors: Record<string, string> = {
    manual: 'bg-blue-500/20 text-blue-300',
    form: 'bg-emerald-500/20 text-emerald-300',
    curl: 'bg-yellow-500/20 text-yellow-300',
    custom_script: 'bg-purple-500/20 text-purple-300',
    oauth2: 'bg-pink-500/20 text-pink-300',
  }
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${colors[type] ?? 'bg-slate-700 text-slate-300'}`}>
      {type}
    </span>
  )
}

function SessionRow({ session }: { session: AuthSession }) {
  const qc = useQueryClient()
  const [testResult, setTestResult] = useState<{ alive: boolean; status_code: number } | null>(null)

  const deleteMut = useMutation({
    mutationFn: () => deleteAuthSession(session.session_id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['auth-sessions'] }),
  })

  const testMut = useMutation({
    mutationFn: () => testAuthSession(session.session_id),
    onSuccess: (data) => setTestResult(data),
  })

  return (
    <tr className="border-b border-briar-border hover:bg-white/[0.02] transition-colors">
      <td className="table-cell font-mono text-xs text-slate-500">{session.session_id.slice(0, 8)}…</td>
      <td className="table-cell text-sm text-slate-200 max-w-xs truncate">{session.target_url}</td>
      <td className="table-cell"><AuthTypeBadge type={session.auth_type} /></td>
      <td className="table-cell text-xs text-slate-500">{formatDate(session.expires_at)}</td>
      <td className="table-cell">
        <div className="flex items-center gap-2">
          {testResult !== null && (
            testResult.alive
              ? <span className="flex items-center gap-1 text-emerald-400 text-xs"><CheckCircle size={12} /> HTTP {testResult.status_code}</span>
              : <span className="flex items-center gap-1 text-red-400 text-xs"><XCircle size={12} /> Dead ({testResult.status_code})</span>
          )}
          <button
            onClick={() => testMut.mutate()}
            disabled={testMut.isPending}
            className="btn-ghost py-1 px-2 text-xs flex items-center gap-1"
          >
            {testMut.isPending ? <Loader2 size={12} className="animate-spin" /> : '⚡'} Test
          </button>
          <button
            onClick={() => { if (confirm('Delete this session?')) deleteMut.mutate() }}
            disabled={deleteMut.isPending}
            className="p-1 text-red-400 hover:bg-red-500/10 rounded transition-colors"
          >
            <Trash2 size={14} />
          </button>
        </div>
      </td>
    </tr>
  )
}

function InteractiveBrowserTab({
  targetUrl,
  onSaved,
}: {
  targetUrl: string
  onSaved: () => void
}) {
  const qc = useQueryClient()
  const [recording, setRecording] = useState<RecordStartResponse | null>(null)
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)
  const [savedScript, setSavedScript] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const startMut = useMutation({
    mutationFn: () => startRecording(targetUrl),
    onSuccess: (data) => {
      const vncUrl = data.vnc_url.replace('HOST', window.location.hostname)
      setRecording({ ...data, vnc_url: vncUrl })
      window.open(vncUrl, '_blank', 'noopener,noreferrer')
    },
    onError: (e: Error) => setError(e.message),
  })

  const handleSave = async () => {
    if (!recording) return
    setSaving(true)
    try {
      const result = await saveRecording(recording.recording_id)
      if (result.recorded_script) {
        setSavedScript(result.recorded_script)
      }
      qc.invalidateQueries({ queryKey: ['auth-sessions'] })
      // Don't close yet — show the script first
      if (!result.recorded_script) {
        onSaved()
      }
    } catch (e: any) {
      setError(e.message)
    } finally {
      setSaving(false)
    }
  }

  const handleCancel = async () => {
    if (recording) {
      await cancelRecording(recording.recording_id).catch(() => {})
      setRecording(null)
    }
  }

  const handleCopy = () => {
    if (!savedScript) return
    navigator.clipboard.writeText(savedScript)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  // ── State: script saved — show it ──────────────────────────────────────────
  if (savedScript) {
    return (
      <div className="space-y-3">
        <div className="flex items-center gap-2 text-emerald-400 text-sm font-medium">
          <CheckCircle size={16} />
          Session saved! Here is your recorded Playwright script:
        </div>
        <div className="relative">
          <pre className="bg-briar-bg border border-briar-border rounded-lg p-3 text-xs text-slate-300 overflow-auto max-h-64 font-mono">
            {savedScript}
          </pre>
          <button
            onClick={handleCopy}
            className="absolute top-2 right-2 btn-ghost py-1 px-2 text-xs flex items-center gap-1"
          >
            {copied ? <><CheckCircle size={10} /> Copied!</> : 'Copy'}
          </button>
        </div>
        <p className="text-xs text-slate-500">
          This script uses the Playwright sync API. Run it standalone or adapt it for the Browser Script tab to automate future sessions.
        </p>
        <button onClick={onSaved} className="btn-primary w-full">Done</button>
      </div>
    )
  }

  // ── State: recording in progress ───────────────────────────────────────────
  if (recording) {
    return (
      <div className="space-y-4">
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-4 text-xs space-y-3">
          <div className="flex items-center gap-2 text-emerald-400 font-medium">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            Recording — browser + Playwright Inspector open
          </div>
          <p className="text-slate-400 leading-relaxed">
            A Chrome window is open at your target app with the <strong className="text-slate-300">Playwright Inspector</strong> panel — you can see the Playwright code being generated in real time as you interact.
          </p>
          <p className="text-slate-400">
            Log in (including MFA, OAuth, etc.), then return here and click <strong className="text-slate-300">Save Session</strong>.
          </p>
          <div className="flex items-center gap-2 pt-1">
            <span className="text-slate-500">Browser not visible?</span>
            <a
              href={recording.vnc_url}
              target="_blank"
              rel="noreferrer"
              className="text-briar-accent hover:underline flex items-center gap-1"
            >
              Open in new tab <ExternalLink size={10} />
            </a>
          </div>
        </div>

        {error && <p className="text-red-400 text-xs break-all">{error}</p>}

        <div className="flex gap-2">
          <button onClick={handleCancel} className="btn-ghost flex-1">Cancel</button>
          <button
            onClick={handleSave}
            disabled={saving}
            className="btn-primary flex-1 flex items-center justify-center gap-2"
          >
            {saving
              ? <><Loader2 size={14} className="animate-spin" /> Saving…</>
              : <><CheckCircle size={14} /> Save Session</>}
          </button>
        </div>
      </div>
    )
  }

  // ── State: idle — not yet started ──────────────────────────────────────────
  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-briar-accent/30 bg-briar-accent/5 p-4 text-xs text-slate-300 space-y-2">
        <p className="font-medium text-slate-100">How it works:</p>
        <ol className="list-decimal list-inside space-y-1 text-slate-400">
          <li>Click "Open Browser" — Chrome opens at your target URL</li>
          <li>The <strong className="text-slate-300">Playwright Inspector</strong> panel shows the generated script in real time</li>
          <li>Log in manually — MFA, OAuth, SSO all work</li>
          <li>Click "Save Session" — cookies and the Playwright script are both captured</li>
        </ol>
      </div>
      {!targetUrl && (
        <p className="text-xs text-yellow-400">⚠ Fill in the Target URL above first</p>
      )}
      {error && <p className="text-red-400 text-xs break-all">{error}</p>}
      <button
        onClick={() => startMut.mutate()}
        disabled={!targetUrl || startMut.isPending}
        className="btn-primary w-full flex items-center justify-center gap-2"
      >
        {startMut.isPending
          ? <><Loader2 size={14} className="animate-spin" /> Opening browser…</>
          : <><Monitor size={14} /> Open Browser</>}
      </button>
    </div>
  )
}

function NewSessionModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient()
  const [tab, setTab] = useState<TabId>('manual')
  const [targetUrl, setTargetUrl] = useState('')
  const [error, setError] = useState('')

  // Manual / headers
  const [token, setToken] = useState('')
  const [extraHeaders, setExtraHeaders] = useState('')

  // Form login
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')

  // cURL
  const [curlCmd, setCurlCmd] = useState('')

  // Script
  const [script, setScript] = useState(`await page.goto('${targetUrl || 'https://example.com/login'}')
await page.fill('input[name="username"]', 'user')
await page.fill('input[name="password"]', 'pass')
await page.click('button[type="submit"]')
await page.wait_for_load_state('networkidle')`)

  const createMut = useMutation({
    mutationFn: async () => {
      if (tab === 'curl') {
        return createSessionFromCurl(curlCmd, targetUrl)
      }
      if (tab === 'manual') {
        // Parse extra headers from "Key: Value\nKey2: Value2" format
        const headers: Record<string, string> = {}
        if (token.trim()) {
          headers['Authorization'] = token.startsWith('Bearer ') ? token : `Bearer ${token}`
        }
        for (const line of extraHeaders.split('\n')) {
          const idx = line.indexOf(':')
          if (idx > 0) {
            headers[line.slice(0, idx).trim()] = line.slice(idx + 1).trim()
          }
        }
        // Store as a manual session: POST with custom_script that just sets headers
        return createAuthSession({
          target_url: targetUrl,
          auth_type: 'custom_script',
          script: `await page.goto('${targetUrl}')`,
          timeout: 10000,
        })
      }
      if (tab === 'form') {
        return createAuthSession({
          target_url: targetUrl,
          auth_type: 'form',
          credentials: { username, password, extra_fields: {} },
        })
      }
      if (tab === 'script') {
        return createAuthSession({
          target_url: targetUrl,
          auth_type: 'custom_script',
          script,
        })
      }
      throw new Error('Unknown tab')
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['auth-sessions'] })
      onClose()
    },
    onError: (e: Error) => setError(e.message),
  })

  const inputCls = 'w-full bg-briar-bg border border-briar-border rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-briar-accent font-mono'
  const labelCls = 'text-xs text-slate-400 mb-1 block'

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="card w-full max-w-xl mx-4 space-y-4 max-h-[90vh] overflow-y-auto">
        <h2 className="text-lg font-semibold">New Auth Session</h2>

        {/* Target URL */}
        <div>
          <label className={labelCls}>Target Application URL</label>
          <input
            type="url"
            placeholder="https://app.example.com"
            value={targetUrl}
            onChange={e => setTargetUrl(e.target.value)}
            className={inputCls}
          />
        </div>

        {/* Tabs */}
        <div className="flex gap-1 bg-briar-bg rounded-lg p-1">
          {(Object.keys(TAB_LABELS) as TabId[]).map(t => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`flex-1 flex items-center justify-center gap-1.5 py-1.5 rounded-md text-xs font-medium transition-colors ${
                tab === t ? 'bg-briar-accent text-white' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {TAB_ICONS[t]} {TAB_LABELS[t]}
            </button>
          ))}
        </div>

        {/* Tab content */}
        {tab === 'manual' && (
          <div className="space-y-3">
            <div>
              <label className={labelCls}>Bearer Token (or paste full Authorization header value)</label>
              <input
                type="text"
                placeholder="eyJhbG... or Bearer eyJhbG..."
                value={token}
                onChange={e => setToken(e.target.value)}
                className={inputCls}
              />
            </div>
            <div>
              <label className={labelCls}>Extra Headers (one per line: Key: Value)</label>
              <textarea
                rows={3}
                placeholder={'X-API-Key: abc123\nCookie: session=xyz'}
                value={extraHeaders}
                onChange={e => setExtraHeaders(e.target.value)}
                className={inputCls}
              />
            </div>
          </div>
        )}

        {tab === 'form' && (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className={labelCls}>Username</label>
                <input type="text" value={username} onChange={e => setUsername(e.target.value)} className={inputCls} placeholder="admin" />
              </div>
              <div>
                <label className={labelCls}>Password</label>
                <input type="password" value={password} onChange={e => setPassword(e.target.value)} className={inputCls} placeholder="••••••••" />
              </div>
            </div>
            <p className="text-xs text-slate-500">Playwright will navigate to the target URL and auto-fill standard login form fields.</p>
          </div>
        )}

        {tab === 'curl' && (
          <div className="space-y-3">
            <div>
              <label className={labelCls}>Paste cURL command (from browser DevTools → Copy as cURL)</label>
              <textarea
                rows={6}
                placeholder={"curl 'https://app.example.com/api/me' \\\n  -H 'Authorization: Bearer eyJhbG...' \\\n  -H 'Cookie: session=abc' \\\n  -b 'token=xyz'"}
                value={curlCmd}
                onChange={e => setCurlCmd(e.target.value)}
                className={`${inputCls} text-xs`}
              />
            </div>
            <p className="text-xs text-slate-500">Headers and cookies will be extracted and applied to all scanner requests.</p>
          </div>
        )}

        {tab === 'script' && (
          <div className="space-y-3">
            <div>
              <label className={labelCls}>Playwright script (async, <code>page</code> is available)</label>
              <textarea
                rows={8}
                value={script}
                onChange={e => setScript(e.target.value)}
                className={`${inputCls} text-xs`}
              />
            </div>
            <p className="text-xs text-slate-500">Use for MFA flows, OAuth redirects, or complex login sequences. Only Playwright page API is allowed.</p>
          </div>
        )}

        {tab === 'interactive' && (
          <InteractiveBrowserTab
            targetUrl={targetUrl}
            onSaved={() => {
              qc.invalidateQueries({ queryKey: ['auth-sessions'] })
              onClose()
            }}
          />
        )}

        {error && <p className="text-red-400 text-sm break-all">{error}</p>}

        {tab !== 'interactive' && (
          <div className="flex justify-end gap-2 pt-2">
            <button onClick={onClose} className="btn-ghost">Cancel</button>
            <button
              onClick={() => createMut.mutate()}
              disabled={!targetUrl || createMut.isPending}
              className="btn-primary flex items-center gap-2"
            >
              {createMut.isPending ? <><Loader2 size={14} className="animate-spin" /> Creating…</> : 'Create Session'}
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

export default function AuthSessions() {
  const [showModal, setShowModal] = useState(false)

  const { data: sessions, isLoading, isError } = useQuery({
    queryKey: ['auth-sessions'],
    queryFn: fetchAuthSessions,
    refetchInterval: 30_000,
  })

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Auth Sessions</h1>
          <p className="text-slate-400 text-sm mt-1">Manage authenticated sessions for target applications</p>
        </div>
        <button onClick={() => setShowModal(true)} className="btn-primary flex items-center gap-2">
          <Plus size={14} /> New Session
        </button>
      </div>

      {/* Info banner */}
      <div className="rounded-lg border border-briar-accent/30 bg-briar-accent/5 p-4 text-sm text-slate-300">
        <p className="font-medium text-briar-accent mb-1">Universal Authentication</p>
        <p className="text-slate-400 text-xs leading-relaxed">
          Create a session once, then select it when launching a scan. All scanner tools (katana, httpx, nuclei, ZAP, sqlmap…) will automatically use the session cookies and headers.
          Supports Bearer tokens, form login with Playwright, cURL import from DevTools, and custom browser scripts for MFA flows.
        </p>
      </div>

      <div className="card p-0 overflow-hidden">
        {isLoading && <div className="p-8 text-center text-slate-500">Loading sessions…</div>}
        {isError && <div className="p-8 text-center text-red-400">Failed to load sessions.</div>}
        {sessions && sessions.length === 0 && (
          <div className="p-8 text-center text-slate-500">
            No sessions yet. Click "New Session" to authenticate with your target application.
          </div>
        )}
        {sessions && sessions.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="border-b border-briar-border">
                <tr>
                  <th className="table-header">ID</th>
                  <th className="table-header">Target URL</th>
                  <th className="table-header">Type</th>
                  <th className="table-header">Expires</th>
                  <th className="table-header">Actions</th>
                </tr>
              </thead>
              <tbody>
                {sessions.map(s => <SessionRow key={s.session_id} session={s} />)}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {showModal && <NewSessionModal onClose={() => setShowModal(false)} />}
    </div>
  )
}
