import type { GraphData, Scan, Vulnerability, AuthSession, ToolDefinition } from '../types'

// All requests use relative URLs — the browser always calls back to
// the same host that served the page (the Vite dev server), which then
// proxies to the appropriate backend service via vite.config.ts.
// This works regardless of whether the VM is accessed via localhost,
// an IP address, or a hostname.

async function get<T>(url: string): Promise<T> {
  const res = await fetch(url)
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`${res.status} ${res.statusText}: ${text}`)
  }
  return res.json() as Promise<T>
}

// ── Scans (read via ui-service, proxied through /api) ────────────────────────

export const fetchScans = (): Promise<Scan[]> =>
  get('/api/v1/scans')

export const fetchScan = (id: string): Promise<Scan> =>
  get(`/api/v1/scans/${id}`)

export const fetchScanGraph = (id: string): Promise<GraphData> =>
  get(`/api/v1/scans/${id}/graph`)

export const triggerSync = (id: string): Promise<void> =>
  fetch(`/api/v1/scans/${id}/sync`, { method: 'POST' }).then(() => undefined)

export const cancelScan = async (id: string): Promise<void> => {
  const res = await fetch(`/api/v1/scans/${id}/cancel`, { method: 'POST' })
  if (!res.ok) throw new Error(`Cancel failed: ${res.statusText}`)
}

export const deleteScan = async (id: string): Promise<void> => {
  const res = await fetch(`/api/v1/scans/${id}`, { method: 'DELETE' })
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText)
    throw new Error(`Delete failed: ${text}`)
  }
}

export interface EndpointItem {
  url: string
  method: string
  status_code: number
  content_type: string
  title: string
  tool: string
  has_params: boolean
  param_names: string[]
}

export interface EndpointsResponse {
  total: number
  endpoints: EndpointItem[]
}

export const fetchScanEndpoints = (
  id: string,
  opts: { include_static?: boolean; source?: string } = {},
): Promise<EndpointsResponse> => {
  const qs = new URLSearchParams()
  qs.set('include_static', String(opts.include_static ?? false))
  if (opts.source) qs.set('source', opts.source)
  return get(`/api/v1/scans/${id}/endpoints?${qs}`)
}

export const runTool = async (
  scanId: string,
  tool: string,
  params: Record<string, any> = {},
): Promise<{ scan_id: string; tool: string; status: string }> => {
  const res = await fetch(`/api/v1/scans/${scanId}/run-tool`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tool, params }),
  })
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText)
    throw new Error(`Run tool failed: ${text}`)
  }
  return res.json()
}

// ── Vulnerabilities ───────────────────────────────────────────────────────────

export interface VulnParams {
  scan_id?: string
  severity?: string
  tool?: string
  limit?: number
  deduplicate?: boolean
}

export const fetchVulnerabilities = (params: VulnParams = {}): Promise<Vulnerability[]> => {
  const qs = new URLSearchParams()
  if (params.scan_id) qs.set('scan_id', params.scan_id)
  if (params.severity) qs.set('severity', params.severity)
  if (params.tool) qs.set('tool', params.tool)
  if (params.limit) qs.set('limit', String(params.limit))
  qs.set('deduplicate', String(params.deduplicate ?? true))
  return get(`/api/v1/vulnerabilities?${qs}`)
}

// ── Create scan (via gateway POST /api/v1/scans) ─────────────────────────────

export interface CreateScanPayload {
  target_url: string
  tools: string[]
  auth_session_id?: string | null
}

export async function createScan(
  payload: CreateScanPayload,
  token?: string,
): Promise<{ scan_id: string; status: string }> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }

  // Token is optional — only attach if a non-empty value is provided
  if (token && token.trim()) {
    headers['Authorization'] = `Bearer ${token.trim()}`
  }

  const res = await fetch('/api/v1/scans', {
    method: 'POST',
    headers,
    body: JSON.stringify(payload),
  })

  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText)
    throw new Error(`Create scan failed (${res.status}): ${text}`)
  }
  return res.json()
}

// ── Auth sessions ─────────────────────────────────────────────────────────────

export const fetchAuthSessions = (): Promise<AuthSession[]> =>
  get('/api/v1/auth/sessions')

export const deleteAuthSession = (id: string): Promise<void> =>
  fetch(`/api/v1/auth/sessions/${id}`, { method: 'DELETE' }).then(() => undefined)

export const testAuthSession = (id: string): Promise<{ alive: boolean; status_code: number }> =>
  fetch(`/api/v1/auth/sessions/${id}/test`, { method: 'POST' })
    .then(r => r.json())

export interface CreateSessionPayload {
  target_url: string
  auth_type: string
  credentials?: { username: string; password: string; extra_fields?: Record<string, string> }
  script?: string
  timeout?: number
}

export const createAuthSession = (payload: CreateSessionPayload): Promise<{ session_id: string; expires_at: string; status: string }> => {
  return fetch('/api/v1/auth/sessions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  }).then(async r => {
    if (!r.ok) { const t = await r.text(); throw new Error(`${r.status}: ${t}`) }
    return r.json()
  })
}

export const createSessionFromCurl = (curlCommand: string, targetUrl: string): Promise<{ session_id: string; expires_at: string; status: string }> => {
  return fetch('/api/v1/auth/sessions/from-curl', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ curl_command: curlCommand, target_url: targetUrl }),
  }).then(async r => {
    if (!r.ok) { const t = await r.text(); throw new Error(`${r.status}: ${t}`) }
    return r.json()
  })
}

export interface RecordStartResponse {
  recording_id: string
  vnc_url: string
  status: string
}

export const startRecording = (targetUrl: string): Promise<RecordStartResponse> =>
  fetch('/api/v1/auth/sessions/record/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target_url: targetUrl }),
  }).then(async r => {
    if (!r.ok) { const t = await r.text(); throw new Error(`${r.status}: ${t}`) }
    return r.json()
  })

export const saveRecording = (recordingId: string): Promise<{ session_id: string; expires_at: string; status: string; recorded_script?: string }> =>
  fetch(`/api/v1/auth/sessions/record/${recordingId}/save`, { method: 'POST' })
    .then(async r => {
      if (!r.ok) { const t = await r.text(); throw new Error(`${r.status}: ${t}`) }
      return r.json()
    })

export const cancelRecording = (recordingId: string): Promise<void> =>
  fetch(`/api/v1/auth/sessions/record/${recordingId}`, { method: 'DELETE' }).then(() => undefined)

export const getSessionScript = (sessionId: string): Promise<{ script: string }> =>
  get(`/api/v1/auth/sessions/${sessionId}/script`)

// ── Tool configuration ────────────────────────────────────────────────────────

export const fetchTools = (): Promise<ToolDefinition[]> =>
  get('/api/v1/tools')

export const updateToolConfig = (toolId: string, params: Record<string, any>): Promise<{ saved: boolean }> =>
  fetch(`/api/v1/tools/${toolId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ params }),
  }).then(async r => {
    if (!r.ok) { const t = await r.text(); throw new Error(`${r.status}: ${t}`) }
    return r.json()
  })

// ── WebSocket URL (relative → same host as the page) ─────────────────────────

export function getWsUrl(scanId: string): string {
  // Use the current page's host so this works on any machine, not just localhost
  const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${wsProto}//${window.location.host}/ws/scans/${scanId}`
}
