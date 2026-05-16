export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed'
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export interface ScanStep {
  tool: string
  status: ScanStatus
  started_at?: string | null
  finished_at?: string | null
}

export interface Scan {
  id: string
  target_url: string
  status: ScanStatus
  created_at: string
  updated_at: string
  tools: string[]
  steps: ScanStep[]
}

export interface Vulnerability {
  id: string
  scan_id: string
  tool: string
  severity: Severity
  url: string | null
  vulnerability_type: string | null
  description: string | null
  created_at: string
  count?: number
  affected_urls?: string[]
}

export interface GraphNode {
  id: string
  label: string
  url?: string
  type: 'endpoint' | 'vulnerability' | 'root'
  method?: string
  discovered_by?: string
  severity?: Severity
  tool?: string
  vuln_count?: number
  has_critical?: boolean
  has_high?: boolean
  description?: string
  max_severity?: string
  // react-force-graph internal positioning
  x?: number
  y?: number
  vx?: number
  vy?: number
  fx?: number
  fy?: number
}

export interface GraphLink {
  source: string | GraphNode
  target: string | GraphNode
}

export interface GraphData {
  nodes: GraphNode[]
  links: GraphLink[]
}

export interface AuthSession {
  session_id: string
  target_url: string
  auth_type: 'form' | 'oauth2' | 'custom_script' | 'manual' | 'curl'
  created_at: string
  expires_at: string
  status: string
}

export interface WsEvent {
  event: 'initial_state' | 'step_update' | 'stats_update' | 'scan_complete'
  scan?: Scan
  tool?: string
  status?: ScanStatus
  progress?: number
  scan_status?: ScanStatus
  endpoint_count?: number
  vuln_count?: number
}

export interface ToolParam {
  key: string
  label: string
  description: string
  type: 'string' | 'number' | 'boolean' | 'select' | 'textarea'
  default: any
  value: any
  options?: string[]
  min?: number
  max?: number
}

export interface ToolDefinition {
  id: string
  name: string
  group: 'recon' | 'dast' | 'smart'
  emoji: string
  color: string
  available: boolean
  description: string
  params: ToolParam[]
}

export interface ToolGroup {
  label: string
  description: string
  color: string
}
