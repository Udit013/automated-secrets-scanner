import { NavLink, Link, useLocation } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { getStats } from '../api/client'
import { clsx } from 'clsx'

const NAV = [
  { to: '/', label: 'Overview' },
  { to: '/history', label: 'Scans' },
  { to: '/schedules', label: 'Schedules' },
]

/**
 * Single command bar replacing the traditional sidebar: identity on the
 * left, workspace tabs beside it, system state and the one primary action
 * on the right. Content owns the full width below.
 */
export function TopBar() {
  const location = useLocation()
  const { data: stats, isFetching } = useQuery({
    queryKey: ['stats'],
    queryFn: getStats,
    refetchInterval: 15_000,
  })

  const openCritical = stats?.critical_count ?? 0

  return (
    <header className="sticky top-0 z-20 bg-ink/95 backdrop-blur-sm border-b border-line">
      <div className="mx-auto max-w-page px-6 h-12 flex items-center gap-7">
        {/* Identity */}
        <Link to="/" className="flex items-center gap-2.5 shrink-0 group">
          <Mark />
          <span className="leading-none">
            <span className="block text-[13px] font-semibold tracking-tight">
              CipherWatch
            </span>
            <span className="block text-[9px] font-mono uppercase tracking-kicker text-ivory-mute mt-0.5">
              ops console
            </span>
          </span>
        </Link>

        {/* Workspace tabs */}
        <nav className="flex items-center h-full" aria-label="Primary">
          {NAV.map(({ to, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                clsx(
                  'relative flex items-center h-full px-3 text-[13px] transition-colors',
                  isActive || (to === '/history' && location.pathname.startsWith('/history'))
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

        {/* System state: critical exposure at a glance, always visible */}
        <div
          className="hidden sm:flex items-center gap-2 text-2xs font-mono"
          title={`${openCritical} critical finding(s) across all scans`}
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
            {openCritical > 0 ? `${openCritical} critical` : 'all clear'}
          </span>
        </div>

        <Link to="/scan" className="btn-primary h-7 px-3 text-xs">
          New scan
        </Link>
      </div>
    </header>
  )
}

/** Product mark: a keyhole cut from a solid square. Drawn, not imported. */
function Mark() {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" aria-hidden className="shrink-0">
      <rect x="1" y="1" width="18" height="18" rx="2" className="fill-ivory" />
      <circle cx="10" cy="8" r="2.6" className="fill-ink" />
      <path d="M8.9 9.5 L11.1 9.5 L12 15 L8 15 Z" className="fill-ink" />
    </svg>
  )
}
