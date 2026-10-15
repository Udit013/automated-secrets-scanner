import { NavLink, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { clsx } from 'clsx'
import { getStats } from '../api/client'
import { clearToken } from '../api/auth'
import { useHealth } from '../hooks/useHealth'
import { Mark } from './Mark'

const NAV = [
  { to: '/overview', label: 'Overview' },
  { to: '/projects', label: 'Projects' },
  { to: '/history', label: 'Scans' },
  { to: '/schedules', label: 'Schedules' },
]

/**
 * Single command bar: identity on the left, workspace tabs beside it,
 * live exposure and the one primary action on the right.
 */
export function TopBar() {
  const { data: health } = useHealth()
  const { data: stats, isFetching } = useQuery({
    queryKey: ['stats'],
    queryFn: getStats,
    refetchInterval: 15_000,
  })

  // Open critical *credentials* (deduplicated, triage-aware), not raw lines.
  const openCritical = stats?.exposure?.open_by_severity.CRITICAL ?? 0

  return (
    <header className="sticky top-0 z-20 bg-ink/95 backdrop-blur-sm border-b border-line">
      <div className="mx-auto max-w-page px-4 sm:px-6 h-12 flex items-center gap-4 sm:gap-7">
        <Link to="/overview" className="flex items-center gap-2.5 shrink-0" aria-label="CipherWatch overview">
          <Mark />
          <span className="hidden sm:block leading-none">
            <span className="block text-[13px] font-semibold tracking-tight">CipherWatch</span>
            <span className="block text-[9px] font-mono uppercase tracking-kicker text-ivory-mute mt-0.5">
              exposure ledger
            </span>
          </span>
        </Link>

        <nav className="scroll-strip flex items-center h-full overflow-x-auto min-w-0" aria-label="Primary">
          {NAV.map(({ to, label }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                clsx(
                  'relative flex items-center h-full px-2.5 sm:px-3 text-[13px] whitespace-nowrap transition-colors',
                  isActive
                    ? 'text-ivory font-medium after:absolute after:inset-x-3 after:bottom-0 after:h-px after:bg-ivory'
                    : 'text-ivory-mute hover:text-ivory-dim',
                )
              }
            >
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="flex-1" />

        <Link
          to="/projects"
          className="hidden md:flex items-center gap-2 text-2xs font-mono shrink-0"
          title={`${openCritical} open critical credential(s) across all projects`}
        >
          <span
            className={clsx(
              'h-1.5 w-1.5 rounded-full',
              openCritical > 0 ? 'bg-sev-critical' : 'bg-ok',
              isFetching && 'animate-pulse',
            )}
            aria-hidden
          />
          <span className={openCritical > 0 ? 'text-sev-critical' : 'text-ivory-mute'}>
            {openCritical > 0 ? `${openCritical} critical open` : 'no critical open'}
          </span>
        </Link>

        {health?.auth_required && (
          <button onClick={clearToken} className="btn-ghost h-7 px-2 text-2xs shrink-0" title="Forget the access token on this device">
            Lock
          </button>
        )}

        <Link to="/scan" className="btn-primary h-7 px-3 text-xs shrink-0">
          New scan
        </Link>
      </div>
    </header>
  )
}
