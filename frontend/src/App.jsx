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

/**
 * Row highlight from application-layer DPI (fallback to well-known ports).
 */
function rowClassForPacket(p) {
  const app = String(p.applicationLayer || '').toUpperCase()
  if (app === 'TLS') return 'netlens-row--tls'
  if (app === 'HTTP') return 'netlens-row--http'
  if (app === 'DNS' || String(p.protocol || '').toUpperCase() === 'DNS') {
    return 'netlens-row--dns'
  }
  const port = getDestinationPort(String(p.destination))
  if (port === 443) return 'netlens-row--tls'
  if (port === 80) return 'netlens-row--http'
  return ''
}

/**
 * Build a plain object for the details panel / JSON export (no internal id).
 */
function packetToDetailObject(p) {
  return {
    source: p.source,
    destination: p.destination,
    protocol: p.protocol,
    length: p.length,
    timestamp: p.timestamp,
    applicationLayer: p.applicationLayer || '',
    payloadInfo: p.payloadInfo || '',
  }
}

/**
 * Live filter: substring match on endpoints, payload info, app layer; numeric query matches ports.
 */
function rowMatchesSearch(p, rawQuery) {
  const q = rawQuery.trim().toLowerCase()
  if (!q) return true
  const src = String(p.source).toLowerCase()
  const dst = String(p.destination).toLowerCase()
  const info = String(p.payloadInfo || '').toLowerCase()
  const app = String(p.applicationLayer || '').toLowerCase()
  if (
    src.includes(q) ||
    dst.includes(q) ||
    info.includes(q) ||
    app.includes(q)
  ) {
    return true
  }
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
  const [selectedId, setSelectedId] = useState(null)

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
          payloadInfo: data.payloadInfo ?? '',
          applicationLayer: data.applicationLayer ?? '',
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

  const selectedPacket = useMemo(
    () => packets.find((p) => p.id === selectedId) ?? null,
    [packets, selectedId],
  )

  const toggleFreeze = () => setFrozen((f) => !f)

  const handleRowActivate = (p) => {
    setSelectedId((id) => (id === p.id ? null : p.id))
  }

  const handleRowKeyDown = (e, p) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      handleRowActivate(p)
    }
  }

  const detailJson = selectedPacket
    ? JSON.stringify(packetToDetailObject(selectedPacket), null, 2)
    : ''

  const colCount = 6

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
            {frozen ? 'Resume' : 'Freeze'}
          </button>
          <div className="netlens-status">
            <span
              className={`netlens-live-dot${frozen ? ' netlens-live-dot--paused' : ''}`}
              aria-hidden="true"
              title={frozen ? 'Paused' : 'Live capture'}
            />
            <span className="netlens-live-label">Listening live…</span>
          </div>
        </div>
      </header>

      <main className="netlens-main">
        <div
          className={`netlens-workspace${selectedPacket ? ' netlens-workspace--split' : ''}`}
        >
          <div className="netlens-panel netlens-panel--feed">
            <div className="netlens-panel-head">
              <span className="netlens-panel-title">Packet stream</span>
              <span className="netlens-panel-meta">
                Last {MAX_PACKETS} packets
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
                Filter
              </label>
              <input
                id="netlens-filter"
                type="search"
                className="netlens-search"
                placeholder="IP, port, protocol, or payload text…"
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
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Protocol</th>
                    <th>Length</th>
                    <th>Time</th>
                    <th>Info</th>
                  </tr>
                </thead>
                <tbody>
                  {packets.length === 0 ? (
                    <tr>
                      <td colSpan={colCount} className="netlens-empty">
                        Waiting for connection or no packets yet…
                      </td>
                    </tr>
                  ) : filteredPackets.length === 0 ? (
                    <tr>
                      <td colSpan={colCount} className="netlens-empty">
                        No packets match this filter.
                      </td>
                    </tr>
                  ) : (
                    filteredPackets.map((p) => {
                      const rowClass = [
                        rowClassForPacket(p),
                        selectedId === p.id ? 'netlens-row--selected' : '',
                      ]
                        .filter(Boolean)
                        .join(' ')
                      const infoText =
                        p.payloadInfo && String(p.payloadInfo).trim()
                          ? String(p.payloadInfo)
                          : '—'
                      return (
                        <tr
                          key={p.id}
                          className={rowClass || undefined}
                          tabIndex={0}
                          role="button"
                          aria-pressed={selectedId === p.id}
                          aria-label={`Packet ${p.source} to ${p.destination}`}
                          onClick={() => handleRowActivate(p)}
                          onKeyDown={(e) => handleRowKeyDown(e, p)}
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
                          <td
                            className="netlens-info"
                            title={infoText === '—' ? '' : infoText}
                          >
                            {infoText}
                          </td>
                        </tr>
                      )
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {selectedPacket && (
            <aside
              className="netlens-details"
              aria-label="Packet details"
            >
              <div className="netlens-details-head">
                <h2 className="netlens-details-title">Packet details</h2>
                <button
                  type="button"
                  className="netlens-btn netlens-btn--ghost"
                  onClick={() => setSelectedId(null)}
                >
                  Close
                </button>
              </div>

              <div className="netlens-details-body">
                <section className="netlens-details-section">
                  <h3 className="netlens-details-h3">Decoded fields</h3>
                  <dl className="netlens-details-dl">
                    <dt>Source</dt>
                    <dd className="netlens-mono">{String(selectedPacket.source)}</dd>
                    <dt>Destination</dt>
                    <dd className="netlens-mono">
                      {String(selectedPacket.destination)}
                    </dd>
                    <dt>Protocol</dt>
                    <dd>{String(selectedPacket.protocol)}</dd>
                    <dt>Length</dt>
                    <dd className="netlens-num">{String(selectedPacket.length)}</dd>
                    <dt>Timestamp</dt>
                    <dd className="netlens-mono netlens-ts">
                      {String(selectedPacket.timestamp)}
                    </dd>
                    <dt>Application layer</dt>
                    <dd>
                      {selectedPacket.applicationLayer
                        ? String(selectedPacket.applicationLayer)
                        : '—'}
                    </dd>
                    <dt>Payload / DPI</dt>
                    <dd className="netlens-details-payload">
                      {selectedPacket.payloadInfo
                        ? String(selectedPacket.payloadInfo)
                        : '—'}
                    </dd>
                  </dl>
                </section>

                <section className="netlens-details-section">
                  <h3 className="netlens-details-h3">Raw JSON</h3>
                  <pre className="netlens-details-json">{detailJson}</pre>
                </section>
              </div>
            </aside>
          )}
        </div>
      </main>
    </div>
  )
}

export default App
