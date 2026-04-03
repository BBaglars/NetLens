import { useEffect, useMemo, useRef, useState } from 'react'
import './App.css'

const WS_URL = 'ws://localhost:8080/ws'
const MAX_PACKETS = 50
const APP_TITLE = 'NetLens'
const PPS_WINDOW_MS = 1000
const PPS_TICK_MS = 200

/** Initial protocol toggles: all visible until user narrows the selection. */
const DEFAULT_PROTO_SELECTION = {
  tcp: true,
  udp: true,
  icmp: true,
  dns: true,
}

/**
 * True when backend marked the packet as DNS (UDP/53 DPI).
 */
function isDnsPacket(p) {
  const app = String(p.applicationLayer || '').toUpperCase()
  if (app === 'DNS') return true
  return /^query:/i.test(String(p.payloadInfo || '').trim())
}

/**
 * Coarse transport key from the wire protocol field (ICMPv4 / ICMPv6 → ICMP for filters & styling).
 */
function transportKey(protocol) {
  const u = String(protocol || '').toUpperCase()
  if (u === 'TCP') return 'TCP'
  if (u === 'UDP') return 'UDP'
  if (
    u === 'ICMPV4' ||
    u === 'ICMPV6' ||
    u === 'ICMP' ||
    u.startsWith('ICMP')
  ) {
    return 'ICMP'
  }
  return 'OTHER'
}

/**
 * Label for the Protocol column (DNS overrides bare UDP when applicable).
 */
function displayProtocol(p) {
  if (isDnsPacket(p)) return 'DNS'
  const raw = String(p.protocol || '').toUpperCase()
  if (raw === 'ICMPV6') return 'ICMPv6'
  if (raw === 'ICMPV4') return 'ICMPv4'
  const k = transportKey(p.protocol)
  if (k === 'OTHER') return String(p.protocol || '—')
  return k
}

/**
 * Badge variant for protocol / DNS display.
 */
function protocolBadgeClass(p) {
  if (isDnsPacket(p)) return 'netlens-proto-badge netlens-proto-badge--dns'
  const k = transportKey(p.protocol)
  const base = 'netlens-proto-badge'
  if (k === 'TCP') return `${base} ${base}--tcp`
  if (k === 'UDP') return `${base} ${base}--udp`
  if (k === 'ICMP') return `${base} ${base}--icmp`
  return `${base} ${base}--other`
}

/**
 * Left stripe class: DNS > ICMP > TCP > UDP (DNS is not styled as generic UDP).
 */
function rowStripeClass(p) {
  if (isDnsPacket(p)) return 'netlens-row--stripe-dns'
  const k = transportKey(p.protocol)
  if (k === 'TCP') return 'netlens-row--stripe-tcp'
  if (k === 'ICMP') return 'netlens-row--stripe-icmp'
  if (k === 'UDP') return 'netlens-row--stripe-udp'
  return 'netlens-row--stripe-other'
}

/**
 * Extract TCP/UDP port from host:port or [ipv6]:port.
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
 * Host part of an endpoint for top-destination stats (IPv4 :port, [IPv6]:port, or bare IPv6 for ICMP).
 */
function extractDestinationHost(destination) {
  if (typeof destination !== 'string' || !destination.trim()) return null
  const s = destination.trim()
  if (s.startsWith('[')) {
    const end = s.indexOf(']')
    if (end > 1) return s.slice(1, end)
    return null
  }
  // IPv4 with port: d.d.d.d:port only (single colon before decimal port).
  if (/^(\d{1,3}\.){3}\d{1,3}:\d+$/.test(s)) {
    return s.slice(0, s.lastIndexOf(':'))
  }
  // Bare IPv6 has multiple colons; do not strip "::" segments as a bogus TCP port.
  const colonCount = (s.match(/:/g) || []).length
  if (colonCount >= 2) {
    return s
  }
  const lastColon = s.lastIndexOf(':')
  if (lastColon <= 0) return s
  const after = s.slice(lastColon + 1)
  if (/^\d+$/.test(after)) return s.slice(0, lastColon)
  return s
}

/**
 * JSON-safe detail object for the side panel (no React id).
 */
function packetToDetailObject(p) {
  return {
    source: p.source,
    destination: p.destination,
    protocol: displayProtocol(p),
    length: p.length,
    timestamp: p.timestamp,
    applicationLayer: p.applicationLayer ? String(p.applicationLayer) : '',
    payloadInfo: p.payloadInfo ? String(p.payloadInfo) : '',
    payload: p.payload ? String(p.payload) : '',
  }
}

/**
 * Show packet only if its category toggle is on (DNS is separate from generic UDP).
 */
function matchesProtocolSelection(p, sel) {
  if (isDnsPacket(p)) return sel.dns
  const k = transportKey(p.protocol)
  if (k === 'TCP') return sel.tcp
  if (k === 'ICMP') return sel.icmp
  if (k === 'UDP') return sel.udp
  return false
}

/**
 * Unified search: IP/endpoints (including IPv6 with ':'), payload, DPI, protocol; numeric-only → port match.
 */
function matchesSearchQuery(p, rawQuery) {
  const q = rawQuery.trim()
  if (!q) return true
  const qLower = q.toLowerCase()
  const chunks = [
    p.source,
    p.destination,
    p.payload,
    p.payloadInfo,
    p.applicationLayer,
    p.protocol,
    displayProtocol(p),
  ]
  for (const chunk of chunks) {
    const hay = String(chunk || '').toLowerCase()
    if (hay.includes(qLower)) return true
  }
  // Port shortcut only when the query is digits-only (so "fe80::1" is never parsed as port).
  if (/^\d+$/.test(q)) {
    const port = parseInt(q, 10)
    const ps = getDestinationPort(String(p.source))
    const pd = getDestinationPort(String(p.destination))
    if (ps === port || pd === port) return true
  }
  return false
}

/**
 * Monospace payload block; hex: prefix uses terminal styling via CSS modifier.
 */
function PayloadCodeBlock({ value }) {
  const raw = value == null ? '' : String(value)
  const trimmed = raw.trim()
  if (!trimmed) {
    return <span className="netlens-code netlens-code--empty">—</span>
  }
  const isHex = trimmed.startsWith('hex:')
  return (
    <pre
      className={`netlens-code ${isHex ? 'netlens-code--terminal' : 'netlens-code--plain'}`}
    >
      {raw}
    </pre>
  )
}

function App() {
  const [packets, setPackets] = useState([])
  const [frozen, setFrozen] = useState(false)
  const [protoSel, setProtoSel] = useState(() => ({ ...DEFAULT_PROTO_SELECTION }))
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
          payload: data.payload ?? '',
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
    () =>
      packets.filter(
        (p) =>
          matchesProtocolSelection(p, protoSel) &&
          matchesSearchQuery(p, searchQuery),
      ),
    [packets, protoSel, searchQuery],
  )

  const selectedPacket = useMemo(
    () => packets.find((p) => p.id === selectedId) ?? null,
    [packets, selectedId],
  )

  const toggleProto = (key) => {
    setProtoSel((prev) => ({ ...prev, [key]: !prev[key] }))
  }

  const selectAllProtos = () => {
    setProtoSel({ ...DEFAULT_PROTO_SELECTION })
  }

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
  const allProtoOn = Object.values(protoSel).every(Boolean)

  return (
    <div className="netlens">
      <header className="netlens-header">
        <div className="netlens-brand">
          <img
            className="netlens-logo"
            src="/favicon.png"
            alt="NetLens"
            width={44}
            height={44}
          />
          <div className="netlens-brand-text">
            <h1 className="netlens-title">{APP_TITLE}</h1>
            <p className="netlens-tagline">Live packet intelligence</p>
          </div>
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
                <span className="netlens-stat-label">Total packets</span>
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
                <span className="netlens-stat-label">Top destination</span>
                <span
                  className="netlens-stat-value netlens-stat-value--mono netlens-stat-value--top-dest"
                  title={topDestination}
                >
                  {topDestination}
                </span>
              </div>
            </div>

            <div className="netlens-filter-bar" role="search">
              <div className="netlens-filter-bar__head">
                <span className="netlens-filter-bar__title">Advanced filters</span>
                <button
                  type="button"
                  className="netlens-link-btn"
                  onClick={selectAllProtos}
                  disabled={allProtoOn}
                >
                  Enable all protocols
                </button>
              </div>

              <div className="netlens-filter-bar__proto-row">
                <span className="netlens-filter-bar__label netlens-filter-bar__label--inline">
                  Protocols
                </span>
                <div
                  className="netlens-proto-chips"
                  role="group"
                  aria-label="Filter by protocol"
                >
                  {(
                    [
                      { key: 'tcp', label: 'TCP' },
                      { key: 'udp', label: 'UDP' },
                      { key: 'icmp', label: 'ICMP' },
                      { key: 'dns', label: 'DNS' },
                    ]
                  ).map(({ key, label }) => (
                    <button
                      key={key}
                      type="button"
                      className={`netlens-filter-chip netlens-filter-chip--${key}${protoSel[key] ? ' netlens-filter-chip--active' : ''}`}
                      aria-pressed={protoSel[key]}
                      onClick={() => toggleProto(key)}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>

              <div className="netlens-search-row">
                <label className="netlens-filter-bar__label" htmlFor="netlens-search">
                  Search
                </label>
                <input
                  id="netlens-search"
                  type="text"
                  inputMode="search"
                  className="netlens-search"
                  placeholder="IPv4, IPv6 (::), port, or payload text…"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  autoComplete="off"
                  spellCheck={false}
                />
              </div>
            </div>

            <div className="netlens-table-wrap">
              <table className="netlens-table">
                <thead>
                  <tr>
                    <th className="netlens-th-endpoint">Source</th>
                    <th className="netlens-th-endpoint">Destination</th>
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
                        No packets match filters or search.
                      </td>
                    </tr>
                  ) : (
                    filteredPackets.map((p) => {
                      const rowClass = [
                        rowStripeClass(p),
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
                          <td
                            className="netlens-mono netlens-td-endpoint"
                            title={String(p.source)}
                          >
                            {String(p.source)}
                          </td>
                          <td
                            className="netlens-mono netlens-td-endpoint"
                            title={String(p.destination)}
                          >
                            {String(p.destination)}
                          </td>
                          <td className="netlens-td-protocol">
                            <span className={protocolBadgeClass(p)}>
                              {displayProtocol(p)}
                            </span>
                          </td>
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
            <aside className="netlens-details" aria-label="Packet detail">
              <div className="netlens-details-head">
                <div>
                  <h2 className="netlens-details-title">Packet detail</h2>
                  <p className="netlens-details-sub">Layer summary & raw capture</p>
                </div>
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
                  <h3 className="netlens-details-h3">Layers & endpoints</h3>
                  <dl className="netlens-details-dl">
                    <dt>Source</dt>
                    <dd className="netlens-mono netlens-dd-endpoint">
                      {String(selectedPacket.source)}
                    </dd>
                    <dt>Destination</dt>
                    <dd className="netlens-mono netlens-dd-endpoint">
                      {String(selectedPacket.destination)}
                    </dd>
                    <dt>Protocol</dt>
                    <dd>
                      <span className={protocolBadgeClass(selectedPacket)}>
                        {displayProtocol(selectedPacket)}
                      </span>
                    </dd>
                    <dt>Application layer</dt>
                    <dd>
                      {selectedPacket.applicationLayer
                        ? String(selectedPacket.applicationLayer)
                        : '—'}
                    </dd>
                    <dt>DPI / metadata</dt>
                    <dd className="netlens-details-meta">
                      {selectedPacket.payloadInfo
                        ? String(selectedPacket.payloadInfo)
                        : '—'}
                    </dd>
                    <dt>Timestamp</dt>
                    <dd className="netlens-mono netlens-ts">
                      {String(selectedPacket.timestamp)}
                    </dd>
                    <dt>Length</dt>
                    <dd className="netlens-num">{String(selectedPacket.length)}</dd>
                  </dl>
                </section>

                <section className="netlens-details-section netlens-details-section--payload">
                  <h3 className="netlens-details-h3">Payload (raw)</h3>
                  <PayloadCodeBlock value={selectedPacket.payload} />
                </section>

                <section className="netlens-details-section">
                  <h3 className="netlens-details-h3">JSON</h3>
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
