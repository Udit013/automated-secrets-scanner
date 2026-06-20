import { clsx } from 'clsx'
import type { Severity } from '../api/client'

// GitHub Advanced Security severity palette, rendered as tinted chips.
const MAP: Record<Severity, string> = {
  CRITICAL: 'text-[#F85149] border-[#F85149]/40 bg-[#F85149]/10',
  HIGH: 'text-[#FF7B72] border-[#FF7B72]/40 bg-[#FF7B72]/10',
  MEDIUM: 'text-[#D29922] border-[#D29922]/40 bg-[#D29922]/10',
  LOW: 'text-[#3FB950] border-[#3FB950]/40 bg-[#3FB950]/10',
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={clsx(
        'inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold uppercase tracking-wide border',
        MAP[severity] ?? 'bg-gray-800 text-gray-400 border-gray-700',
      )}
    >
      {severity}
    </span>
  )
}
