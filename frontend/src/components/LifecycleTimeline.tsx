import { format } from 'date-fns'
import { GitCommit, Users, CalendarClock, Clock } from 'lucide-react'
import type { Finding } from '../api/client'

/**
 * Secret Lifecycle — exposure intelligence derived from Git history.
 * Only rendered when the finding carries lifecycle data.
 */
export function LifecycleTimeline({ finding: f }: { finding: Finding }) {
  if (!f.introduced_at && !f.last_seen_at) return null

  const fmt = (d: string | null) => (d ? format(new Date(d), 'MMM d, yyyy') : '—')

  return (
    <div className="rounded border border-gray-700 bg-gray-950 p-4">
      <div className="text-xs font-semibold uppercase tracking-wide text-gray-500 mb-3">
        Secret Lifecycle
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-sm">
        <Field icon={<CalendarClock size={13} />} label="Introduced" value={fmt(f.introduced_at)} />
        <Field icon={<CalendarClock size={13} />} label="Last Seen" value={fmt(f.last_seen_at)} />
        <Field
          icon={<Clock size={13} />}
          label="Exposure"
          value={f.exposure_days != null ? `${f.exposure_days} day${f.exposure_days === 1 ? '' : 's'}` : '—'}
        />
        <Field
          icon={<GitCommit size={13} />}
          label="Commits"
          value={f.commits_affected != null ? String(f.commits_affected) : '—'}
        />
        <Field
          icon={<Users size={13} />}
          label="Authors"
          value={f.authors_count != null ? String(f.authors_count) : '—'}
        />
      </div>

      {/* Simple exposure bar */}
      {f.exposure_days != null && f.exposure_days > 0 && (
        <div className="mt-4">
          <div className="flex items-center justify-between text-[11px] text-gray-500 mb-1 font-mono">
            <span>{fmt(f.introduced_at)}</span>
            <span>{f.exposure_days}d exposed</span>
            <span>{fmt(f.last_seen_at)}</span>
          </div>
          <div className="h-1.5 w-full rounded-full bg-gray-800 overflow-hidden">
            <div
              className="h-full rounded-full bg-[#D29922]"
              style={{ width: `${Math.min(100, (f.exposure_days / 30) * 100)}%` }}
            />
          </div>
        </div>
      )}
    </div>
  )
}

function Field({
  icon,
  label,
  value,
}: {
  icon: React.ReactNode
  label: string
  value: string
}) {
  return (
    <div>
      <div className="flex items-center gap-1 text-xs text-gray-500 mb-1">
        {icon} {label}
      </div>
      <div className="text-sm text-gray-200 font-mono">{value}</div>
    </div>
  )
}
