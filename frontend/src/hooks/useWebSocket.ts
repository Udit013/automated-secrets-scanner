import { useEffect, useRef, useState } from 'react'
import { API_BASE_URL } from '../api/client'
import { getToken } from '../api/auth'

export interface WsMessage {
  event: 'started' | 'progress' | 'completed' | 'failed'
  progress?: number
  message?: string
  total_findings?: number
  files_scanned?: number
  error?: string
}

export function useWebSocket(scanId: string | null) {
  const [lastMessage, setLastMessage] = useState<WsMessage | null>(null)
  const [connected, setConnected] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)

  useEffect(() => {
    if (!scanId) return

    // In dev: connect directly to localhost:8000 (Vite can't proxy WS).
    // In prod: connect to the Render backend URL from VITE_API_URL.
    let wsBase: string
    if (API_BASE_URL) {
      // e.g. https://secrets-scanner-api.onrender.com → wss://...
      wsBase = API_BASE_URL.replace(/^http/, 'ws')
    } else {
      const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
      const host = import.meta.env.DEV ? 'localhost:8000' : window.location.host
      wsBase = `${protocol}://${host}`
    }
    const url = `${wsBase}/api/v1/scans/ws/${scanId}`

    // The access token (private workspaces) rides in the subprotocol list,
    // the one handshake header a browser lets us set; it never enters the URL.
    const token = getToken()
    const ws = new WebSocket(url, token ? ['cipherwatch.v1', `bearer.${token}`] : undefined)
    wsRef.current = ws

    ws.onopen = () => setConnected(true)
    ws.onclose = () => setConnected(false)
    ws.onerror = () => setConnected(false)
    ws.onmessage = (e) => {
      try {
        const msg: WsMessage = JSON.parse(e.data)
        setLastMessage(msg)
      } catch {
        // ignore malformed frames
      }
    }

    return () => {
      ws.close()
    }
  }, [scanId])

  return { lastMessage, connected }
}
