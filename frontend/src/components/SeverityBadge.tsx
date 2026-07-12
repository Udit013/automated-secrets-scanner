import type { Severity } from '../api/client'

export const SEV_COLOR: Record<Severity, string> = {
  CRITICAL: '#F2545B',
  HIGH: '#EE7A3B',
  MEDIUM: '#D9A514',
  LOW: '#7E9CC9',
}

export const SEV_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

/**
 * Severity is typographic, not a pill: a small tick of the status color
 * beside a tracked label. The color never appears without the word.
 */
export function SeverityBadge({ severity }: { severity: Severity }) {
  const color = SEV_COLOR[severity]
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
      <span
        className="h-2.5 w-[3px] rounded-full"
        style={{ backgroundColor: color }}
        aria-hidden
      />
      <span
        className="text-2xs font-medium uppercase tracking-kicker"
        style={{ color }}
      >
        {severity.toLowerCase()}
      </span>
    </span>
  )
}
