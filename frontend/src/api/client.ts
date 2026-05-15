import type { GraphData, Scan, Vulnerability } from '../types'

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

// ── Vulnerabilities ───────────────────────────────────────────────────────────

export interface VulnParams {
  scan_id?: string
  severity?: string
  tool?: string
  limit?: number
}

export const fetchVulnerabilities = (params: VulnParams = {}): Promise<Vulnerability[]> => {
  const qs = new URLSearchParams()
  if (params.scan_id) qs.set('scan_id', params.scan_id)
  if (params.severity) qs.set('severity', params.severity)
  if (params.tool) qs.set('tool', params.tool)
  if (params.limit) qs.set('limit', String(params.limit))
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

// ── WebSocket URL (relative → same host as the page) ─────────────────────────

export function getWsUrl(scanId: string): string {
  // Use the current page's host so this works on any machine, not just localhost
  const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${wsProto}//${window.location.host}/ws/scans/${scanId}`
}
