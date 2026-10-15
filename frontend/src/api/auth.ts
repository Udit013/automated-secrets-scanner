import { useSyncExternalStore } from 'react'

/*
 * Access-token store for private workspaces (backend ACCESS_TOKEN set).
 *
 * The token lives in sessionStorage by default, so it is gone when the tab
 * closes; "remember on this device" moves it to localStorage. Either way it
 * is only ever sent to the API origin, in the Authorization header (or the
 * WebSocket subprotocol), never in a URL.
 */

const KEY = 'cipherwatch.token'

type State = { token: string; locked: boolean }

function read(): string {
  try {
    return sessionStorage.getItem(KEY) ?? localStorage.getItem(KEY) ?? ''
  } catch {
    return ''
  }
}

let state: State = { token: read(), locked: false }
const listeners = new Set<() => void>()

function emit(next: State) {
  state = next
  listeners.forEach((l) => l())
}

export function getToken(): string {
  return state.token
}

export function setToken(token: string, remember: boolean) {
  try {
    sessionStorage.removeItem(KEY)
    localStorage.removeItem(KEY)
    ;(remember ? localStorage : sessionStorage).setItem(KEY, token)
  } catch {
    // Storage unavailable (private mode): keep the token in memory only.
  }
  emit({ token, locked: false })
}

export function clearToken() {
  try {
    sessionStorage.removeItem(KEY)
    localStorage.removeItem(KEY)
  } catch {
    /* ignore */
  }
  emit({ token: '', locked: true })
}

/** Called by the API client on any 401: forget the token and show the unlock screen. */
export function markLocked() {
  if (!state.locked) clearToken()
}

function subscribe(listener: () => void) {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

export function useAuthState(): State {
  return useSyncExternalStore(subscribe, () => state)
}
