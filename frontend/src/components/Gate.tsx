import { useState } from 'react'
import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import { apiErrorMessage, verifyToken } from '../api/client'
import { setToken, useAuthState } from '../api/auth'
import { useHealth } from '../hooks/useHealth'
import { Mark } from './Mark'

/**
 * Everything behind the console needs two facts first: is the API reachable,
 * and does this workspace require a token? Free-tier hosts sleep, so the
 * first request can take ~30s; say so instead of showing a blank page.
 */
export function Gate({ children }: { children: ReactNode }) {
  const health = useHealth()
  const auth = useAuthState()

  if (health.isLoading) {
    return (
      <Centered>
        <p className="font-mono text-2xs text-ivory-dim animate-pulse" role="status">
          connecting to the CipherWatch API…
        </p>
        <p className="text-2xs text-ivory-mute mt-2 max-w-xs">
          A sleeping free-tier server can take up to a minute to wake on the first visit.
        </p>
      </Centered>
    )
  }
  if (health.error) {
    return (
      <Centered>
        <p className="font-mono text-2xs text-sev-critical" role="alert">✕ {apiErrorMessage(health.error)}</p>
        <button onClick={() => health.refetch()} className="btn-outline h-7 text-2xs mt-4">
          Try again
        </button>
      </Centered>
    )
  }
  if (health.data!.auth_required && (!auth.token || auth.locked)) return <Unlock />
  return <>{children}</>
}

function Unlock() {
  const [value, setValue] = useState('')
  const [remember, setRemember] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const qc = useQueryClient()

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    const token = value.trim()
    if (!token) return
    setBusy(true)
    setError(null)
    try {
      await verifyToken(token)
      setToken(token, remember)
      qc.invalidateQueries()
    } catch (err) {
      setError(
        isAxiosError(err) && err.response?.status === 401
          ? 'That token was not accepted.'
          : apiErrorMessage(err),
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <Centered>
      <Mark size={28} />
      <h1 className="page-title mt-4">Private workspace</h1>
      <p className="text-2xs text-ivory-mute mt-2 max-w-xs">
        This CipherWatch server requires an access token. It is the <span className="font-mono">ACCESS_TOKEN</span>{' '}
        value set by whoever deployed it.
      </p>
      <form onSubmit={submit} className="mt-6 w-full max-w-xs text-left space-y-4">
        <div>
          <label htmlFor="token" className="field-label">Access token</label>
          <input
            id="token"
            type="password"
            autoComplete="current-password"
            className="field font-mono text-2xs"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            autoFocus
            required
          />
        </div>
        <label className="flex items-center gap-2.5 cursor-pointer">
          <input
            type="checkbox"
            checked={remember}
            onChange={(e) => setRemember(e.target.checked)}
            className="h-3.5 w-3.5 accent-[#ECEAE6]"
          />
          <span className="text-2xs text-ivory-dim">Remember on this device</span>
        </label>
        {error && (
          <p className="text-2xs font-mono text-sev-critical" role="alert">
            ✕ {error}
          </p>
        )}
        <button type="submit" className="btn-primary w-full" disabled={busy || !value.trim()}>
          {busy ? 'Checking…' : 'Unlock'}
        </button>
      </form>
      <Link to="/" className="text-2xs text-ivory-mute hover:text-ivory mt-8">
        ← about CipherWatch
      </Link>
    </Centered>
  )
}

function Centered({ children }: { children: ReactNode }) {
  return (
    <main className="min-h-screen flex flex-col items-center justify-center text-center px-6">{children}</main>
  )
}
