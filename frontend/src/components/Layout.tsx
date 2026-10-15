import { Outlet, Link } from 'react-router-dom'
import { TopBar } from './TopBar'
import { useHealth } from '../hooks/useHealth'

export function Layout() {
  const { data: health } = useHealth()
  return (
    <div className="min-h-screen flex flex-col">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-30 btn-primary"
      >
        Skip to content
      </a>
      <TopBar />
      {health && !health.auth_required && (
        <div className="border-b border-line bg-ink-raised">
          <p className="mx-auto max-w-page px-4 sm:px-6 py-2 text-2xs text-ivory-dim">
            <span className="font-mono text-sev-medium mr-2">{health.demo ? 'demo workspace' : 'public workspace'}</span>
            {health.demo
              ? 'Seeded with sample repositories and fake credentials. Anything you scan here is visible to every visitor.'
              : 'No access token is configured, so anyone with this URL can use it. Set ACCESS_TOKEN to make it private.'}
          </p>
        </div>
      )}
      <main id="main" className="flex-1 w-full mx-auto max-w-page px-4 sm:px-6 py-8">
        <Outlet />
      </main>
      <footer className="mx-auto max-w-page w-full px-4 sm:px-6 py-5 border-t border-line/60 flex flex-wrap justify-between gap-2">
        <p className="text-2xs font-mono text-ivory-mute">
          cipherwatch {health ? `v${health.version}` : ''} · patterns + entropy + git history · secrets never stored
        </p>
        <Link to="/" className="text-2xs text-ivory-mute hover:text-ivory">
          about
        </Link>
      </footer>
    </div>
  )
}
