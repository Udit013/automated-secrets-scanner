import { useEffect, useRef, useState } from 'react'

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

    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
    // In dev, Vite proxies HTTP but not WS — connect directly to backend
    const host = import.meta.env.DEV ? 'localhost:8000' : window.location.host
    const url = `${protocol}://${host}/api/v1/scans/ws/${scanId}`

    const ws = new WebSocket(url)
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
