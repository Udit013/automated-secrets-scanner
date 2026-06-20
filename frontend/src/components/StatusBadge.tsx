import { clsx } from 'clsx'
import type { ScanStatus } from '../api/client'

const MAP: Record<ScanStatus, string> = {
  queued: 'bg-gray-800 text-gray-400 border-gray-700',
  running: 'bg-[#58A6FF]/10 text-[#58A6FF] border-[#58A6FF]/40',
  completed: 'bg-[#3FB950]/10 text-[#3FB950] border-[#3FB950]/40',
  failed: 'bg-[#F85149]/10 text-[#F85149] border-[#F85149]/40',
}

export function StatusBadge({ status }: { status: ScanStatus }) {
  return (
    <span
      className={clsx(
        'inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-medium border capitalize',
        MAP[status],
      )}
    >
      {status === 'running' && (
        <span className="h-1.5 w-1.5 rounded-full bg-[#58A6FF] animate-pulse" />
      )}
      {status}
    </span>
  )
}
