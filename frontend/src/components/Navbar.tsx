import { NavLink } from 'react-router-dom'
import { ShieldCheck, Search, History, CalendarClock, BarChart2 } from 'lucide-react'
import { clsx } from 'clsx'

const links = [
  { to: '/', label: 'Dashboard', icon: BarChart2 },
  { to: '/scan', label: 'New Scan', icon: Search },
  { to: '/history', label: 'History', icon: History },
  { to: '/schedules', label: 'Schedules', icon: CalendarClock },
]

export function Navbar() {
  return (
    <nav className="h-screen w-56 bg-gray-900 border-r border-gray-800 flex flex-col flex-shrink-0">
      <div className="flex items-center gap-2 px-5 py-5 border-b border-gray-800">
        <ShieldCheck className="text-brand-500" size={22} />
        <span className="font-bold text-white text-sm leading-tight">
          Secrets<br />Scanner
        </span>
      </div>

      <div className="flex-1 py-4 space-y-1 px-2">
        {links.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors',
                isActive
                  ? 'bg-brand-500/20 text-brand-400 font-semibold'
                  : 'text-gray-400 hover:text-gray-100 hover:bg-gray-800',
              )
            }
          >
            <Icon size={16} />
            {label}
          </NavLink>
        ))}
      </div>

      <div className="px-5 py-4 border-t border-gray-700 text-xs text-gray-600">
        v2.1.0 · DevSecOps
      </div>
    </nav>
  )
}
