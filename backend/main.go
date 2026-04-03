package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
)

// PacketData is the wire format for browser/clients; JSON tags keep field names stable over the WebSocket API.
type PacketData struct {
	Source      string    `json:"source"`
	Destination string    `json:"destination"`
	Protocol    string    `json:"protocol"`
	Length      int       `json:"length"`
	Timestamp   time.Time `json:"timestamp"`
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

// tcpFlowString builds "IP:port" endpoints when both network and TCP layers are present.
// IPv6 addresses are bracketed so the colon in the address does not collide with port syntax.
func tcpFlowString(network gopacket.NetworkLayer, tcp *layers.TCP) (src, dst string, ok bool) {
	switch n := network.(type) {
	case *layers.IPv4:
		return fmt.Sprintf("%s:%d", n.SrcIP, tcp.SrcPort),
			fmt.Sprintf("%s:%d", n.DstIP, tcp.DstPort),
			true
	case *layers.IPv6:
		return fmt.Sprintf("[%s]:%d", n.SrcIP, tcp.SrcPort),
			fmt.Sprintf("[%s]:%d", n.DstIP, tcp.DstPort),
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

// runCapture decodes live frames in the background so the HTTP server can accept WebSocket clients immediately.
func runCapture(h *hub, handle *pcap.Handle) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		// TCP sits above an IP network layer; both checks skip ARP, UDP, ICMP, etc.
		netLayer := packet.NetworkLayer()
		transLayer := packet.TransportLayer()
		if netLayer == nil || transLayer == nil {
			continue
		}
		tcp, ok := transLayer.(*layers.TCP)
		if !ok {
			continue
		}

		src, dst, ok := tcpFlowString(netLayer, tcp)
		if !ok {
			continue
		}

		pd := PacketData{
			Source:      src,
			Destination: dst,
			Protocol:    "TCP",
			Length:      packetLength(packet),
			Timestamp:   packetTimestamp(packet),
		}

		body, err := json.Marshal(pd)
		if err != nil {
			continue
		}

		// Non-blocking from the capture's perspective: broadcast holds hub lock briefly per packet.
		h.broadcast(body)
	}
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
		snaplen       int32 = 1600
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

