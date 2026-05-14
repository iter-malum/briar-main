import { useEffect, useRef, useState } from 'react'
import type { WsEvent } from '../types'

interface UseWebSocketReturn {
  lastEvent: WsEvent | null
  connected: boolean
}

export function useWebSocket(url: string | null): UseWebSocketReturn {
  const [lastEvent, setLastEvent] = useState<WsEvent | null>(null)
  const [connected, setConnected] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)
  const retryRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const activeUrl = useRef<string | null>(null)

  useEffect(() => {
    if (!url) return

    activeUrl.current = url

    function connect() {
      if (activeUrl.current !== url) return

      const ws = new WebSocket(url)
      wsRef.current = ws

      ws.onopen = () => setConnected(true)

      ws.onmessage = (e) => {
        try {
          const data: WsEvent = JSON.parse(e.data)
          setLastEvent(data)
        } catch {
          // ignore malformed frames
        }
      }

      ws.onclose = () => {
        setConnected(false)
        // Reconnect after 4s unless the component unmounted or URL changed
        retryRef.current = setTimeout(() => {
          if (activeUrl.current === url) connect()
        }, 4000)
      }

      ws.onerror = () => ws.close()
    }

    connect()

    return () => {
      activeUrl.current = null
      if (retryRef.current) clearTimeout(retryRef.current)
      wsRef.current?.close()
    }
  }, [url])

  return { lastEvent, connected }
}
