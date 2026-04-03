import { useEffect, useRef, useState } from 'react'
import './App.css'

const WS_URL = 'ws://localhost:8080/ws'
const MAX_PACKETS = 50
const APP_TITLE = 'NetLens'

/**
 * Extract TCP/UDP destination port from a "host:port" or "[ipv6]:port" string.
 */
function getDestinationPort(destination) {
  if (typeof destination !== 'string') return null
  const bracketed = destination.match(/\]:(\d+)$/)
  if (bracketed) return parseInt(bracketed[1], 10)
  const tail = destination.match(/:(\d+)$/)
  if (tail) return parseInt(tail[1], 10)
  return null
}

function rowClassForPort(port) {
  if (port === 443) return 'netlens-row--https'
  if (port === 80) return 'netlens-row--http'
  return ''
}

function App() {
  const [packets, setPackets] = useState([])
  const packetIdRef = useRef(0)

  useEffect(() => {
    // Open persistent WebSocket to the local capture agent
    const ws = new WebSocket(WS_URL)

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        const entry = {
          id: ++packetIdRef.current,
          source: data.source ?? '—',
          destination: data.destination ?? '—',
          protocol: data.protocol ?? '—',
          length: data.length ?? '—',
          timestamp: data.timestamp ?? '—',
        }
        // Prepend so newest appears on top; keep only the last MAX_PACKETS rows
        setPackets((prev) => [entry, ...prev].slice(0, MAX_PACKETS))
      } catch {
        // Ignore malformed JSON
      }
    }

    return () => {
      // Clean up socket when the component unmounts
      ws.close()
    }
  }, [])

  return (
    <div className="netlens">
      <header className="netlens-header">
        <div className="netlens-brand">
          <span className="netlens-logo" aria-hidden="true" />
          <h1 className="netlens-title">{APP_TITLE}</h1>
        </div>
        <div className="netlens-status">
          <span
            className="netlens-live-dot"
            aria-hidden="true"
            title="Live capture"
          />
          <span className="netlens-live-label">Canlı Dinleniyor...</span>
        </div>
      </header>

      <main className="netlens-main">
        <div className="netlens-panel">
          <div className="netlens-panel-head">
            <span className="netlens-panel-title">Paket akışı</span>
            <span className="netlens-panel-meta">
              Son {MAX_PACKETS} paket
            </span>
          </div>
          <div className="netlens-table-wrap">
            <table className="netlens-table">
              <thead>
                <tr>
                  <th>Kaynak</th>
                  <th>Hedef</th>
                  <th>Protokol</th>
                  <th>Uzunluk</th>
                  <th>Zaman</th>
                </tr>
              </thead>
              <tbody>
                {packets.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="netlens-empty">
                      Bağlantı bekleniyor veya henüz paket yok…
                    </td>
                  </tr>
                ) : (
                  packets.map((p) => {
                    const port = getDestinationPort(p.destination)
                    return (
                      <tr
                        key={p.id}
                        className={rowClassForPort(port)}
                      >
                        <td className="netlens-mono">{String(p.source)}</td>
                        <td className="netlens-mono">
                          {String(p.destination)}
                        </td>
                        <td>{String(p.protocol)}</td>
                        <td className="netlens-num">{String(p.length)}</td>
                        <td className="netlens-mono netlens-ts">
                          {String(p.timestamp)}
                        </td>
                      </tr>
                    )
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      </main>
    </div>
  )
}

export default App
