import { Outlet } from 'react-router-dom'
import { TopBar } from './TopBar'

export function Layout() {
  return (
    <div className="min-h-screen flex flex-col">
      <TopBar />
      <main className="flex-1 w-full mx-auto max-w-page px-6 py-8">
        <Outlet />
      </main>
      <footer className="mx-auto max-w-page w-full px-6 py-5 border-t border-line/60">
        <p className="text-2xs font-mono text-ivory-mute">
          secrets-scanner v2.1 · pattern + entropy + heuristics
        </p>
      </footer>
    </div>
  )
}
