import { clsx } from 'clsx'
import type { ScanStatus } from '../api/client'

const LABEL: Record<ScanStatus, string> = {
  queued: 'queued',
  running: 'running',
  completed: 'complete',
  failed: 'failed',
}

/** Status as annotated text, not a pill. Running state carries the pulse. */
export function StatusBadge({ status }: { status: ScanStatus }) {
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1.5 text-2xs font-mono',
        status === 'failed' && 'text-sev-critical',
        status === 'completed' && 'text-ivory-dim',
        status === 'running' && 'text-ivory',
        status === 'queued' && 'text-ivory-mute',
      )}
    >
      <span
        className={clsx(
          'h-1.5 w-1.5 rounded-full',
          status === 'running' && 'bg-ivory animate-pulse',
          status === 'completed' && 'bg-ok',
          status === 'failed' && 'bg-sev-critical',
          status === 'queued' && 'bg-ivory-mute',
        )}
        aria-hidden
      />
      {LABEL[status]}
    </span>
  )
}
