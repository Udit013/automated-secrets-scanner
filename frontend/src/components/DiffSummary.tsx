import { ArrowUpRight, ArrowDownRight, Minus, GitCompare } from 'lucide-react'
import { format } from 'date-fns'
import type { ScanDiff } from '../api/client'
import { clsx } from 'clsx'

/**
 * Differential scanning summary — compares a scan against the previous scan
 * of the same source. Renders nothing meaningful when there's no baseline.
 */
export function DiffSummary({ diff, compact = false }: { diff: ScanDiff; compact?: boolean }) {
  if (!diff.has_baseline) {
    return (
      <div className="card flex items-center gap-2 text-sm text-gray-500">
        <GitCompare size={14} />
        No previous scan of this source to compare against — this is the baseline.
      </div>
    )
  }

  const improved = diff.net_change < 0
  const worse = diff.net_change > 0

  return (
    <div className="card">
      <div className="flex items-center gap-2 mb-3">
        <GitCompare size={14} className="text-brand-500" />
        <h2 className="text-sm font-semibold text-gray-300">Change Since Last Scan</h2>
        {diff.baseline_created_at && (
          <span className="text-xs text-gray-600 ml-auto font-mono">
            baseline {format(new Date(diff.baseline_created_at), 'MMM d, HH:mm')}
          </span>
        )}
      </div>

      <div className={clsx('grid gap-3', compact ? 'grid-cols-3' : 'grid-cols-3')}>
        <Stat
          icon={<ArrowUpRight size={14} />}
          label="New"
          value={diff.new_count}
          color="#F85149"
        />
        <Stat
          icon={<ArrowDownRight size={14} />}
          label="Resolved"
          value={diff.resolved_count}
          color="#3FB950"
        />
        <Stat
          icon={<Minus size={14} />}
          label="Unchanged"
          value={diff.unchanged_count}
          color="#8B949E"
        />
      </div>

      <div
        className="mt-3 flex items-center justify-center gap-2 rounded border px-3 py-2 text-sm font-medium"
        style={{
          color: improved ? '#3FB950' : worse ? '#F85149' : '#8B949E',
          borderColor: improved ? '#3FB95040' : worse ? '#F8514940' : '#30363D',
          backgroundColor: improved ? '#3FB95010' : worse ? '#F8514910' : 'transparent',
        }}
      >
        {improved && <ArrowDownRight size={15} />}
        {worse && <ArrowUpRight size={15} />}
        {improved
          ? `Net Improvement: ${diff.net_change}`
          : worse
          ? `Net Increase: +${diff.net_change}`
          : 'No net change'}
      </div>
    </div>
  )
}

function Stat({
  icon,
  label,
  value,
  color,
}: {
  icon: React.ReactNode
  label: string
  value: number
  color: string
}) {
  return (
    <div className="rounded border border-gray-700 bg-gray-950 px-3 py-2 text-center">
      <div className="flex items-center justify-center gap-1 text-xs" style={{ color }}>
        {icon}
        {label}
      </div>
      <div className="text-xl font-bold font-mono mt-1" style={{ color }}>
        {value}
      </div>
    </div>
  )
}
