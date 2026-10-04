import { format } from 'date-fns'
import type { ScanDiff } from '../api/client'

/**
 * Differential summary as a single ledger line: three measured columns and
 * a verdict, separated by hairlines. Compare-against-baseline reads like a
 * balance statement, not a card grid.
 */
export function DiffSummary({ diff }: { diff: ScanDiff }) {
  if (!diff.has_baseline) {
    return (
      <p className="text-2xs font-mono text-ivory-mute">
        no baseline — first scan of this source
      </p>
    )
  }

  const net = diff.net_change
  const verdictColor = net < 0 ? '#57AB5A' : net > 0 ? '#F2545B' : '#888681'

  return (
    <div className="panel">
      <div className="flex items-center justify-between px-4 pt-3">
        <span className="kicker">Change since last scan</span>
        {diff.baseline_created_at && (
          <span className="text-2xs font-mono text-ivory-mute">
            baseline · {format(new Date(diff.baseline_created_at), 'MMM d HH:mm')}
          </span>
        )}
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-4 divide-x divide-line px-1 py-3">
        <Cell label="new" value={diff.new_count} sign="+" color={diff.new_count > 0 ? '#F2545B' : undefined} />
        <Cell label="resolved" value={diff.resolved_count} sign="−" color={diff.resolved_count > 0 ? '#57AB5A' : undefined} />
        <Cell label="unchanged" value={diff.unchanged_count} />
        <div className="px-4">
          <div className="kicker mb-1">net</div>
          <div className="font-mono text-lg font-medium tabular-nums leading-none" style={{ color: verdictColor }}>
            {net > 0 ? `+${net}` : net}
            <span className="ml-2 text-2xs font-sans font-medium normal-nums">
              {net < 0 ? 'improved' : net > 0 ? 'regressed' : 'steady'}
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}

function Cell({
  label,
  value,
  sign,
  color,
}: {
  label: string
  value: number
  sign?: string
  color?: string
}) {
  return (
    <div className="px-4">
      <div className="kicker mb-1">{label}</div>
      <div
        className="font-mono text-lg font-medium tabular-nums leading-none"
        style={{ color: color ?? '#A8A5A0' }}
      >
        {value > 0 && sign ? sign : ''}
        {value}
      </div>
    </div>
  )
}
