import { clsx } from 'clsx'
import type { Severity, ScanStatus } from '../types'

const STATUS_STYLES: Record<ScanStatus, string> = {
  pending:   'bg-slate-700 text-slate-300',
  running:   'bg-blue-900/60 text-blue-300 animate-pulse',
  completed: 'bg-emerald-900/60 text-emerald-300',
  failed:    'bg-red-900/60 text-red-300',
}

const SEV_STYLES: Record<Severity, string> = {
  info:     'bg-slate-700 text-slate-300',
  low:      'bg-sky-900/60 text-sky-300',
  medium:   'bg-yellow-900/60 text-yellow-300',
  high:     'bg-orange-900/60 text-orange-300',
  critical: 'bg-red-900/60 text-red-400 font-semibold',
}

interface Props {
  value: string
  variant?: 'status' | 'severity'
}

export function StatusBadge({ value, variant = 'status' }: Props) {
  const styles =
    variant === 'severity'
      ? SEV_STYLES[value as Severity] ?? 'bg-slate-700 text-slate-300'
      : STATUS_STYLES[value as ScanStatus] ?? 'bg-slate-700 text-slate-300'

  return (
    <span className={clsx('inline-flex items-center px-2 py-0.5 rounded text-xs', styles)}>
      {value}
    </span>
  )
}
