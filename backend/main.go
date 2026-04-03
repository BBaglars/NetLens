package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
)

// PacketData is the wire format for browser/clients; JSON tags keep field names stable over the WebSocket API.
// Source and Destination are strings long enough for any textual IP (IPv4 dotted quad; IPv6 as eight 4-digit hex groups).
// L4 endpoints use host:port for IPv4 and [host]:port for IPv6.
type PacketData struct {
	Source           string    `json:"source"`
	Destination      string    `json:"destination"`
	Protocol         string    `json:"protocol"` // TCP, UDP, ICMPv4, ICMPv6
	Payload          string    `json:"payload,omitempty"`
	Length           int       `json:"length"`
	Timestamp        time.Time `json:"timestamp"`
	PayloadInfo      string    `json:"payloadInfo,omitempty"`
	ApplicationLayer string    `json:"applicationLayer,omitempty"`
}

// hub tracks active WebSocket connections and broadcasts JSON payloads with one writer at a time per connection.
type hub struct {
	mu      sync.Mutex
	clients map[*websocket.Conn]struct{}
}

func newHub() *hub {
	return &hub{clients: make(map[*websocket.Conn]struct{})}
}

func (h *hub) register(c *websocket.Conn) {
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
}

func (h *hub) unregister(c *websocket.Conn) {
	h.mu.Lock()
	delete(h.clients, c)
	h.mu.Unlock()
}

// broadcast sends one JSON text frame to every client; failed writes remove the client (closed browser, network drop, etc.).
func (h *hub) broadcast(payload []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()

	var dead []*websocket.Conn
	for c := range h.clients {
		if err := c.WriteMessage(websocket.TextMessage, payload); err != nil {
			dead = append(dead, c)
		}
	}
	for _, c := range dead {
		_ = c.Close()
		delete(h.clients, c)
	}
}

var upgrader = websocket.Upgrader{
	// CheckOrigin allows any origin so local HTML/tools can connect during development; tighten for production.
	CheckOrigin: func(r *http.Request) bool { return true },
}

// formatIP returns a canonical string for an IPv4 or IPv6 address (IPv6 uses net.IP.String() / RFC 5952).
func formatIP(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

// tcpFlowString builds "IP:port" endpoints when both network and TCP layers are present.
// IPv6 addresses are bracketed so the colon in the address does not collide with port syntax.
func tcpFlowString(network gopacket.NetworkLayer, tcp *layers.TCP) (src, dst string, ok bool) {
	switch n := network.(type) {
	case *layers.IPv4:
		return fmt.Sprintf("%s:%d", formatIP(n.SrcIP), tcp.SrcPort),
			fmt.Sprintf("%s:%d", formatIP(n.DstIP), tcp.DstPort),
			true
	case *layers.IPv6:
		return fmt.Sprintf("[%s]:%d", formatIP(n.SrcIP), tcp.SrcPort),
			fmt.Sprintf("[%s]:%d", formatIP(n.DstIP), tcp.DstPort),
			true
	default:
		return "", "", false
	}
}

// udpFlowString builds "IP:port" endpoints for UDP over IPv4/IPv6 (same formatting rules as TCP).
func udpFlowString(network gopacket.NetworkLayer, udp *layers.UDP) (src, dst string, ok bool) {
	switch n := network.(type) {
	case *layers.IPv4:
		return fmt.Sprintf("%s:%d", formatIP(n.SrcIP), udp.SrcPort),
			fmt.Sprintf("%s:%d", formatIP(n.DstIP), udp.DstPort),
			true
	case *layers.IPv6:
		return fmt.Sprintf("[%s]:%d", formatIP(n.SrcIP), udp.SrcPort),
			fmt.Sprintf("[%s]:%d", formatIP(n.DstIP), udp.DstPort),
			true
	default:
		return "", "", false
	}
}

func packetTimestamp(packet gopacket.Packet) time.Time {
	if md := packet.Metadata(); md != nil {
		if !md.Timestamp.IsZero() {
			return md.Timestamp
		}
	}
	return time.Now()
}

func packetLength(packet gopacket.Packet) int {
	if md := packet.Metadata(); md != nil {
		return md.CaptureLength
	}
	return len(packet.Data())
}

// maxPayloadField limits JSON/WebSocket size; very large captures are truncated in the text field.
const maxPayloadField = 4096

// payloadToReadableString turns raw layer bytes into a JSON-safe string: printable ASCII as UTF-8 text, otherwise a hex prefix.
func payloadToReadableString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	total := len(b)
	out := b
	suffix := ""
	if len(out) > maxPayloadField {
		out = b[:maxPayloadField]
		suffix = fmt.Sprintf(" … [truncated, %d bytes total]", total)
	}
	if isPrintablePayload(out) {
		return string(out) + suffix
	}
	return "hex:" + hex.EncodeToString(out) + suffix
}

// isPrintablePayload allows common whitespace; extended/binary data forces hex encoding for stable JSON.
func isPrintablePayload(b []byte) bool {
	for _, c := range b {
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			return false
		}
		if c > 0x7e {
			return false
		}
	}
	return true
}

// ipEndpointPair returns host-only endpoints for ICMP (no ports), using canonical IP strings.
func ipEndpointPair(network gopacket.NetworkLayer) (src, dst string, ok bool) {
	switch n := network.(type) {
	case *layers.IPv4:
		return formatIP(n.SrcIP), formatIP(n.DstIP), true
	case *layers.IPv6:
		return formatIP(n.SrcIP), formatIP(n.DstIP), true
	default:
		return "", "", false
	}
}

// packetIPv4OrIPv6Network returns the IPv4 or IPv6 layer when present (LayerTypeIPv4 / LayerTypeIPv6).
func packetIPv4OrIPv6Network(packet gopacket.Packet) gopacket.NetworkLayer {
	if l := packet.Layer(layers.LayerTypeIPv4); l != nil {
		if v4, ok := l.(*layers.IPv4); ok {
			return v4
		}
	}
	if l := packet.Layer(layers.LayerTypeIPv6); l != nil {
		if v6, ok := l.(*layers.IPv6); ok {
			return v6
		}
	}
	return nil
}

// icmpPayloadInfo builds a consistent Type/Code summary for ICMPv4 and ICMPv6 (including echo request/reply).
func icmpPayloadInfo(typeVal, codeVal uint8) string {
	return fmt.Sprintf("Type: %d Code: %d", typeVal, codeVal)
}

const (
	tlsHandshake       = 22
	tlsHandshakeClient = 1
	tlsExtServerName   = 0
)

// extractSNIFromTLS parses the first TLS record for a ClientHello and returns the first host_name SNI, if any.
func extractSNIFromTLS(payload []byte) string {
	exts := extractTLSClientHelloExtensions(payload)
	if len(exts) == 0 {
		return ""
	}
	return parseSNIFromExtensions(exts)
}

// extractTLSClientHelloExtensions returns the extensions blob from the first ClientHello in the TCP payload.
func extractTLSClientHelloExtensions(payload []byte) []byte {
	if len(payload) < 5 {
		return nil
	}
	// TLS record: type, version, length, fragment
	if payload[0] != tlsHandshake {
		return nil
	}
	recLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if 5+recLen > len(payload) {
		return nil
	}
	frag := payload[5 : 5+recLen]
	if len(frag) < 4 {
		return nil
	}
	if frag[0] != tlsHandshakeClient {
		return nil
	}
	bodyLen := int(frag[1])<<16 | int(frag[2])<<8 | int(frag[3])
	if 4+bodyLen > len(frag) {
		return nil
	}
	body := frag[4 : 4+bodyLen]
	// client_version (2) + random (32)
	off := 34
	if off >= len(body) {
		return nil
	}
	sidLen := int(body[off])
	off++
	if off+sidLen > len(body) {
		return nil
	}
	off += sidLen
	if off+2 > len(body) {
		return nil
	}
	csLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if off+csLen > len(body) {
		return nil
	}
	off += csLen
	if off+1 > len(body) {
		return nil
	}
	compLen := int(body[off])
	off++
	if off+compLen > len(body) {
		return nil
	}
	off += compLen
	if off+2 > len(body) {
		return nil
	}
	extLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if off+extLen > len(body) || extLen == 0 {
		return nil
	}
	return body[off : off+extLen]
}

// parseSNIFromExtensions walks TLS extension blocks and decodes RFC 6066 server_name (host_name).
func parseSNIFromExtensions(exts []byte) string {
	i := 0
	for i+4 <= len(exts) {
		etype := binary.BigEndian.Uint16(exts[i : i+2])
		elen := int(binary.BigEndian.Uint16(exts[i+2 : i+4]))
		i += 4
		if elen < 0 || i+elen > len(exts) {
			break
		}
		edata := exts[i : i+elen]
		if etype == tlsExtServerName && len(edata) >= 2 {
			listLen := int(binary.BigEndian.Uint16(edata[0:2]))
			if 2+listLen > len(edata) || listLen < 4 {
				i += elen
				continue
			}
			list := edata[2 : 2+listLen]
			nameType := list[0]
			nameLen := int(binary.BigEndian.Uint16(list[1:3]))
			if nameType != 0 || nameLen <= 0 || 3+nameLen > len(list) {
				i += elen
				continue
			}
			host := string(list[3 : 3+nameLen])
			if host != "" {
				return host
			}
		}
		i += elen
	}
	return ""
}

// extractHTTPRequestInfo parses an HTTP/1.x request line and Host header from the TCP payload.
func extractHTTPRequestInfo(payload []byte) (method, requestTarget, host string) {
	if len(payload) == 0 {
		return "", "", ""
	}
	// Split headers from body crudely; we only need the first request + headers block.
	headerEnd := bytes.Index(payload, []byte("\r\n\r\n"))
	var block []byte
	if headerEnd >= 0 {
		block = payload[:headerEnd]
	} else {
		block = payload
	}
	lines := bytes.Split(block, []byte("\r\n"))
	if len(lines) == 0 {
		return "", "", ""
	}
	first := string(lines[0])
	parts := strings.SplitN(first, " ", 3)
	if len(parts) < 2 {
		return "", "", ""
	}
	method = parts[0]
	if !isHTTPMethodToken(method) {
		return "", "", ""
	}
	requestTarget = parts[1]
	for _, line := range lines[1:] {
		lower := bytes.ToLower(line)
		if bytes.HasPrefix(lower, []byte("host:")) {
			host = strings.TrimSpace(string(line[5:]))
			break
		}
	}
	return method, requestTarget, host
}

// isHTTPMethodToken accepts common HTTP methods (RFC 9110 token: uppercase letters for typical clients).
func isHTTPMethodToken(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for _, r := range s {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}

// inspectTCPApplicationLayer uses ports and payload heuristics to populate DPI fields for TCP.
func inspectTCPApplicationLayer(tcp *layers.TCP, payload []byte) (appLayer, payloadInfo string) {
	if len(payload) == 0 {
		return "", ""
	}
	dst := tcp.DstPort
	src := tcp.SrcPort

	switch {
	case dst == 443:
		appLayer = "TLS"
		if sni := extractSNIFromTLS(payload); sni != "" {
			payloadInfo = "SNI: " + sni
		}
	case dst == 80:
		method, target, host := extractHTTPRequestInfo(payload)
		if method != "" {
			appLayer = "HTTP"
			payloadInfo = method + " " + target
			if host != "" {
				payloadInfo += " | Host: " + host
			}
		}
	case src == 80:
		// Optional: HTTP responses are ignored for Method/Host extraction.
		return "", ""
	default:
		return "", ""
	}
	return appLayer, payloadInfo
}

// inspectDNSLayer reads the first question name using a decoded DNS layer when present, otherwise decodes UDP payload.
func inspectDNSLayer(packet gopacket.Packet, udp *layers.UDP) string {
	if layer := packet.Layer(layers.LayerTypeDNS); layer != nil {
		if dns, ok := layer.(*layers.DNS); ok && len(dns.Questions) > 0 {
			return string(dns.Questions[0].Name)
		}
	}
	var dns layers.DNS
	if err := dns.DecodeFromBytes(udp.Payload, gopacket.NilDecodeFeedback); err != nil {
		return ""
	}
	if len(dns.Questions) == 0 {
		return ""
	}
	return string(dns.Questions[0].Name)
}

// runCapture decodes live frames in the background so the HTTP server can accept WebSocket clients immediately.
// Only IPv4 and IPv6 frames are processed; each frame matches at most one of TCP, UDP, ICMPv4, or ICMPv6.
func runCapture(h *hub, handle *pcap.Handle) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		// Only IPv4 / IPv6 (skips ARP and other non-IP L3 frames).
		netLayer := packetIPv4OrIPv6Network(packet)
		if netLayer == nil {
			continue
		}

		// LayerType* constants are registered with gopacket and match packet.Layer(...) lookups.
		if lay := packet.Layer(layers.LayerTypeTCP); lay != nil {
			tcp, ok := lay.(*layers.TCP)
			if !ok {
				continue
			}
			src, dst, ok := tcpFlowString(netLayer, tcp)
			if !ok {
				continue
			}
			raw := tcp.Payload
			appLayer, pInfo := inspectTCPApplicationLayer(tcp, raw)

			pd := PacketData{
				Source:           src,
				Destination:      dst,
				Protocol:         "TCP",
				Payload:          payloadToReadableString(raw),
				Length:           packetLength(packet),
				Timestamp:        packetTimestamp(packet),
				PayloadInfo:      pInfo,
				ApplicationLayer: appLayer,
			}
			emitPacket(h, pd)
			continue
		}

		if lay := packet.Layer(layers.LayerTypeUDP); lay != nil {
			udp, ok := lay.(*layers.UDP)
			if !ok {
				continue
			}
			src, dst, ok := udpFlowString(netLayer, udp)
			if !ok {
				continue
			}
			raw := udp.Payload
			appLayer, pInfo := "", ""
			if udp.SrcPort == 53 || udp.DstPort == 53 {
				if q := inspectDNSLayer(packet, udp); q != "" {
					appLayer = "DNS"
					pInfo = "Query: " + q
				}
			}

			pd := PacketData{
				Source:           src,
				Destination:      dst,
				Protocol:         "UDP",
				Payload:          payloadToReadableString(raw),
				Length:           packetLength(packet),
				Timestamp:        packetTimestamp(packet),
				PayloadInfo:      pInfo,
				ApplicationLayer: appLayer,
			}
			emitPacket(h, pd)
			continue
		}

		if lay := packet.Layer(layers.LayerTypeICMPv4); lay != nil {
			icmp4, ok := lay.(*layers.ICMPv4)
			if !ok {
				continue
			}
			src, dst, ok := ipEndpointPair(netLayer)
			if !ok {
				continue
			}
			raw := icmp4.LayerPayload()

			pd := PacketData{
				Source:      src,
				Destination: dst,
				Protocol:    "ICMPv4",
				Payload:     payloadToReadableString(raw),
				Length:      packetLength(packet),
				Timestamp:   packetTimestamp(packet),
				PayloadInfo: icmpPayloadInfo(icmp4.TypeCode.Type(), icmp4.TypeCode.Code()),
			}
			emitPacket(h, pd)
			continue
		}

		if lay := packet.Layer(layers.LayerTypeICMPv6); lay != nil {
			icmp6, ok := lay.(*layers.ICMPv6)
			if !ok {
				continue
			}
			src, dst, ok := ipEndpointPair(netLayer)
			if !ok {
				continue
			}
			raw := icmp6.LayerPayload()
			// Echo Request (128) / Echo Reply (129) and all other ICMPv6 types use the same summary shape.
			pInfo := icmpPayloadInfo(icmp6.TypeCode.Type(), icmp6.TypeCode.Code())

			pd := PacketData{
				Source:      src,
				Destination: dst,
				Protocol:    "ICMPv6",
				Payload:     payloadToReadableString(raw),
				Length:      packetLength(packet),
				Timestamp:   packetTimestamp(packet),
				PayloadInfo: pInfo,
			}
			emitPacket(h, pd)
			continue
		}
	}
}

// emitPacket marshals and broadcasts a single PacketData record.
func emitPacket(h *hub, pd PacketData) {
	body, err := json.Marshal(pd)
	if err != nil {
		return
	}
	h.broadcast(body)
}

func main() {
	// Load key=value pairs from .env in the working directory (project root when you `go run` there).
	if err := godotenv.Load(); err != nil {
		log.Fatalf("godotenv.Load: %v", err)
	}

	iface := os.Getenv("NETWORK_INTERFACE")
	if iface == "" {
		log.Fatal("NETWORK_INTERFACE is not set or empty; set it in .env to your pcap device name (e.g. \\Device\\NPF_{...} on Windows)")
	}

	const (
		snaplen       int32 = 65535 // large enough for jumbo DNS / TLS ClientHello in one frame
		promiscuous         = true
		readTimeout         = 2 * time.Second // wakes blocked reads periodically; avoids hanging forever on idle links
	)

	// OpenLive opens an Npcap/libpcap capture handle; promiscuous mode requests delivery of non-unicast-to-us frames when the segment allows it.
	handle, err := pcap.OpenLive(iface, snaplen, promiscuous, readTimeout)
	if err != nil {
		log.Fatalf("pcap.OpenLive(%q): %v", iface, err)
	}
	defer handle.Close()

	h := newHub()

	go runCapture(h, handle)

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("WebSocket yükseltme hatası: %v", err)
			return
		}

		log.Println("Yeni bir istemci bağlandı")
		h.register(conn)

		// Read loop consumes control frames and detects client disconnect; required alongside WriteMessage from the capture goroutine.
		go func(c *websocket.Conn) {
			defer func() {
				h.unregister(c)
				_ = c.Close()
			}()
			for {
				if _, _, err := c.ReadMessage(); err != nil {
					return
				}
			}
		}(conn)
	})

	log.Println("WebSocket sunucusu 8080 portunda başlatıldı")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("HTTP sunucusu: %v", err)
	}
}
