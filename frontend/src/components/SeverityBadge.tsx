import { clsx } from 'clsx'
import type { Severity } from '../api/client'

const MAP: Record<Severity, string> = {
  CRITICAL: 'bg-red-900 text-red-300 border-red-700',
  HIGH: 'bg-orange-900 text-orange-300 border-orange-700',
  MEDIUM: 'bg-yellow-900 text-yellow-300 border-yellow-700',
  LOW: 'bg-blue-900 text-blue-300 border-blue-700',
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={clsx(
        'inline-flex items-center px-2 py-0.5 rounded text-xs font-bold border',
        MAP[severity] ?? 'bg-gray-800 text-gray-400 border-gray-700',
      )}
    >
      {severity}
    </span>
  )
}
