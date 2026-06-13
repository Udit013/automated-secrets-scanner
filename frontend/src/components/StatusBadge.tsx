import { clsx } from 'clsx'
import type { ScanStatus } from '../api/client'

const MAP: Record<ScanStatus, string> = {
  queued: 'bg-gray-800 text-gray-300',
  running: 'bg-blue-900 text-blue-300 animate-pulse',
  completed: 'bg-green-900 text-green-300',
  failed: 'bg-red-900 text-red-300',
}

export function StatusBadge({ status }: { status: ScanStatus }) {
  return (
    <span className={clsx('inline-flex px-2 py-0.5 rounded text-xs font-medium', MAP[status])}>
      {status}
    </span>
  )
}
