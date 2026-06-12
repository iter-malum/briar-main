import { clsx } from 'clsx'
import type { Severity, ScanStatus } from '../types'

const STATUS_STYLES: Record<ScanStatus, string> = {
  pending:   'bg-slate-800 text-slate-400 border border-slate-700',
  running:   'bg-amber-500/10 text-amber-400 border border-amber-500/30 animate-pulse-slow',
  completed: 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/25',
  failed:    'bg-red-500/10 text-red-400 border border-red-500/25',
}

const SEV_STYLES: Record<Severity, string> = {
  info:     'bg-slate-800 text-slate-400 border border-slate-700',
  low:      'bg-sky-500/10 text-sky-400 border border-sky-500/25',
  medium:   'bg-yellow-500/10 text-yellow-300 border border-yellow-500/25',
  high:     'bg-orange-500/10 text-orange-400 border border-orange-500/25',
  critical: 'bg-red-500/15 text-red-400 border border-red-500/30 font-semibold',
}

interface Props {
  value: string
  variant?: 'status' | 'severity'
}

export function StatusBadge({ value, variant = 'status' }: Props) {
  const styles =
    variant === 'severity'
      ? SEV_STYLES[value as Severity] ?? 'bg-slate-800 text-slate-400'
      : STATUS_STYLES[value as ScanStatus] ?? 'bg-slate-800 text-slate-400'

  return (
    <span className={clsx('inline-flex items-center px-2 py-0.5 rounded text-xs', styles)}>
      {value}
    </span>
  )
}
