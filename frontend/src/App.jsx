import { useEffect, useMemo, useRef, useState } from 'react'
import './App.css'

const WS_URL = 'ws://localhost:8080/ws'
const MAX_PACKETS = 50
const APP_TITLE = 'NetLens'
const PPS_WINDOW_MS = 1000
const PPS_TICK_MS = 200

/**
 * Extract TCP/UDP destination port from a "host:port" or "[ipv6]:port" string.
 */
function getDestinationPort(endpoint) {
  if (typeof endpoint !== 'string') return null
  const bracketed = endpoint.match(/\]:(\d+)$/)
  if (bracketed) return parseInt(bracketed[1], 10)
  const tail = endpoint.match(/:(\d+)$/)
  if (tail) return parseInt(tail[1], 10)
  return null
}

/**
 * Extract host/IP portion from an endpoint string (IPv4 host:port or [IPv6]:port).
 */
function extractDestinationHost(destination) {
  if (typeof destination !== 'string' || !destination.trim()) return null
  const s = destination.trim()
  if (s.startsWith('[')) {
    const end = s.indexOf(']')
    if (end > 1) return s.slice(1, end)
    return null
  }
  const lastColon = s.lastIndexOf(':')
  if (lastColon <= 0) return s
  const after = s.slice(lastColon + 1)
  if (/^\d+$/.test(after)) return s.slice(0, lastColon)
  return s
}

function rowClassForPort(port) {
  if (port === 443) return 'netlens-row--https'
  if (port === 80) return 'netlens-row--http'
  return ''
}

/**
 * Live filter: substring match on source/destination; numeric query matches ports.
 */
function rowMatchesSearch(p, rawQuery) {
  const q = rawQuery.trim().toLowerCase()
  if (!q) return true
  const src = String(p.source).toLowerCase()
  const dst = String(p.destination).toLowerCase()
  if (src.includes(q) || dst.includes(q)) return true
  if (/^\d+$/.test(q)) {
    const port = parseInt(q, 10)
    const ps = getDestinationPort(String(p.source))
    const pd = getDestinationPort(String(p.destination))
    if (ps === port || pd === port) return true
  }
  return false
}

function App() {
  const [packets, setPackets] = useState([])
  const [frozen, setFrozen] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [totalPackets, setTotalPackets] = useState(0)
  const [pps, setPps] = useState(0)
  const [topDestination, setTopDestination] = useState('—')

  const packetIdRef = useRef(0)
  const frozenRef = useRef(false)
  const recentPacketTimesRef = useRef([])
  const destinationBytesRef = useRef(new Map())

  useEffect(() => {
    frozenRef.current = frozen
  }, [frozen])

  // Sliding-window PPS based on packet arrival timestamps
  useEffect(() => {
    const id = window.setInterval(() => {
      const now = Date.now()
      recentPacketTimesRef.current = recentPacketTimesRef.current.filter(
        (t) => now - t < PPS_WINDOW_MS,
      )
      setPps(recentPacketTimesRef.current.length)
    }, PPS_TICK_MS)
    return () => window.clearInterval(id)
  }, [])

  useEffect(() => {
    const ws = new WebSocket(WS_URL)

    ws.onmessage = (event) => {
      if (frozenRef.current) return

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

        setTotalPackets((n) => n + 1)

        const now = Date.now()
        recentPacketTimesRef.current.push(now)

        const host = extractDestinationHost(String(entry.destination))
        if (host) {
          const byteLen = Number(entry.length)
          const delta = Number.isFinite(byteLen) ? byteLen : 0
          const map = destinationBytesRef.current
          map.set(host, (map.get(host) || 0) + delta)
          let bestHost = '—'
          let bestBytes = -1
          for (const [h, b] of map) {
            if (b > bestBytes) {
              bestBytes = b
              bestHost = h
            }
          }
          setTopDestination(bestHost)
        }

        setPackets((prev) => [entry, ...prev].slice(0, MAX_PACKETS))
      } catch {
        // Ignore malformed JSON
      }
    }

    return () => {
      ws.close()
    }
  }, [])

  const filteredPackets = useMemo(
    () => packets.filter((p) => rowMatchesSearch(p, searchQuery)),
    [packets, searchQuery],
  )

  const toggleFreeze = () => setFrozen((f) => !f)

  return (
    <div className="netlens">
      <header className="netlens-header">
        <div className="netlens-brand">
          <span className="netlens-logo" aria-hidden="true" />
          <h1 className="netlens-title">{APP_TITLE}</h1>
        </div>
        <div className="netlens-header-right">
          <button
            type="button"
            className={`netlens-btn netlens-btn--freeze${frozen ? ' netlens-btn--active' : ''}`}
            onClick={toggleFreeze}
            aria-pressed={frozen}
          >
            {frozen ? 'Devam' : 'Dondur'}
          </button>
          <div className="netlens-status">
            <span
              className={`netlens-live-dot${frozen ? ' netlens-live-dot--paused' : ''}`}
              aria-hidden="true"
              title={frozen ? 'Paused' : 'Live capture'}
            />
            <span className="netlens-live-label">Canlı Dinleniyor...</span>
          </div>
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

          <div className="netlens-stats">
            <div className="netlens-stat-card">
              <span className="netlens-stat-label">Total Packets</span>
              <span className="netlens-stat-value netlens-stat-value--mono">
                {totalPackets.toLocaleString()}
              </span>
            </div>
            <div className="netlens-stat-card">
              <span className="netlens-stat-label">Current PPS</span>
              <span className="netlens-stat-value netlens-stat-value--mono">
                {pps.toLocaleString()}
              </span>
            </div>
            <div className="netlens-stat-card">
              <span className="netlens-stat-label">Top Destination</span>
              <span
                className="netlens-stat-value netlens-stat-value--mono netlens-stat-value--truncate"
                title={topDestination}
              >
                {topDestination}
              </span>
            </div>
          </div>

          <div className="netlens-toolbar">
            <label className="netlens-search-label" htmlFor="netlens-filter">
              Filtre
            </label>
            <input
              id="netlens-filter"
              type="search"
              className="netlens-search"
              placeholder="IP veya port (örn. 192.168 veya 443)…"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
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
                ) : filteredPackets.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="netlens-empty">
                      Filtreyle eşleşen paket yok.
                    </td>
                  </tr>
                ) : (
                  filteredPackets.map((p) => {
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
