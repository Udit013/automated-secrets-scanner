import { format } from 'date-fns'
import type { Finding } from '../api/client'

/**
 * Secret lifecycle as an actual timeline: introduced → last seen drawn as
 * a measured span with endpoints, annotated with commits and authors.
 */
export function LifecycleTimeline({ finding: f }: { finding: Finding }) {
  if (!f.introduced_at && !f.last_seen_at) return null

  const fmt = (d: string | null) => (d ? format(new Date(d), 'MMM d, yyyy') : '—')
  const days = f.exposure_days ?? 0
  // Span width scales against a 90-day window so short exposures read short.
  const spanPct = Math.max(8, Math.min(100, (days / 90) * 100))

  return (
    <div className="well px-4 py-3.5">
      <div className="flex items-baseline justify-between mb-3">
        <span className="kicker">Lifecycle</span>
        <span className="text-2xs font-mono text-ivory-dim">
          {f.commits_affected != null && `${f.commits_affected} commits`}
          {f.commits_affected != null && f.authors_count != null && ' · '}
          {f.authors_count != null && `${f.authors_count} author${f.authors_count === 1 ? '' : 's'}`}
        </span>
      </div>

      <div style={{ width: `${spanPct}%` }} className="min-w-[180px]">
        <div className="relative h-2 flex items-center">
          <span className="absolute left-0 h-2 w-2 rounded-full bg-sev-medium" />
          <span className="mx-1 flex-1 border-t border-dashed border-sev-medium/60" />
          <span className="absolute right-0 h-2 w-2 rounded-full ring-2 ring-sev-medium bg-ink-inset" />
        </div>
        <div className="flex justify-between mt-1.5 gap-4">
          <div>
            <div className="text-2xs font-mono text-ivory">{fmt(f.introduced_at)}</div>
            <div className="text-2xs text-ivory-mute">introduced</div>
          </div>
          <div className="text-right">
            <div className="text-2xs font-mono text-ivory">{fmt(f.last_seen_at)}</div>
            <div className="text-2xs text-ivory-mute">last seen</div>
          </div>
        </div>
      </div>

      {f.exposure_days != null && (
        <p className="mt-2.5 text-2xs text-ivory-dim">
          Exposed for{' '}
          <span className="font-mono text-sev-medium">
            {f.exposure_days} day{f.exposure_days === 1 ? '' : 's'}
          </span>{' '}
          of repository history
        </p>
      )}
    </div>
  )
}
