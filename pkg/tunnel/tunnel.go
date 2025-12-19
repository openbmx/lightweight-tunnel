package tunnel

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"strconv"
	"sync"
	"time"

	"github.com/openbmx/lightweight-tunnel/internal/config"
	"github.com/openbmx/lightweight-tunnel/pkg/crypto"
	"github.com/openbmx/lightweight-tunnel/pkg/faketcp"
	"github.com/openbmx/lightweight-tunnel/pkg/fec"
	"github.com/openbmx/lightweight-tunnel/pkg/nat"
	"github.com/openbmx/lightweight-tunnel/pkg/p2p"
	"github.com/openbmx/lightweight-tunnel/pkg/routing"
)

const (
	PacketTypeData       = 0x01
	PacketTypeKeepalive  = 0x02
	PacketTypePeerInfo   = 0x03 // Peer discovery/advertisement
	PacketTypeRouteInfo  = 0x04 // Route information exchange
	PacketTypePublicAddr = 0x05 // Server tells client its public address
	PacketTypePunch      = 0x06 // Server requests simultaneous hole-punch

	// IPv4 constants
	IPv4Version      = 4
	IPv4SrcIPOffset  = 12
	IPv4DstIPOffset  = 16
	IPv4MinHeaderLen = 20

	// P2P timing constants
	P2PRegistrationDelay   = 100 * time.Millisecond // Delay to ensure peer registration completes
	P2PHandshakeWaitTime   = 2 * time.Second        // Time to wait for P2P handshake to complete before updating routes
	P2PMaxRetries          = 5
	P2PMaxBackoffSeconds   = 32 // Maximum backoff delay in seconds
)

// ClientConnection represents a single client connection
type ClientConnection struct {
	conn      *faketcp.Conn
	sendQueue chan []byte
	recvQueue chan []byte
	clientIP  net.IP
	stopCh    chan struct{}
	stopOnce  sync.Once
	wg        sync.WaitGroup
	// lastPeerInfo stores the last peer info string sent by this client
	lastPeerInfo string
	mu           sync.RWMutex
}

// Tunnel represents a lightweight tunnel
type Tunnel struct {
	config     *config.Config
	fec        *fec.FEC
	cipher     *crypto.Cipher               // Encryption cipher (nil if no key)
	conn       *faketcp.Conn                // Used in client mode
	listener   *faketcp.Listener            // Used in server mode
	clients    map[string]*ClientConnection // Used in server mode (key: IP address)
	clientsMux sync.RWMutex
	tunName    string
	tunFile    *TunDevice
	stopCh     chan struct{}
	stopOnce   sync.Once // Ensures Stop() is only executed once
	wg         sync.WaitGroup
	sendQueue  chan []byte // Used in client mode
	recvQueue  chan []byte // Used in client mode

	// P2P and routing
	p2pManager    *p2p.Manager          // P2P connection manager
	routingTable  *routing.RoutingTable // Routing table
	myTunnelIP    net.IP                // My tunnel IP address
	publicAddr    string                // Public address as seen by server (for NAT traversal)
	publicAddrMux sync.RWMutex          // Protects publicAddr
	connMux       sync.Mutex           // Protects t.conn during reconnects
}

// NewTunnel creates a new tunnel instance
func NewTunnel(cfg *config.Config) (*Tunnel, error) {
	// Create FEC encoder/decoder
	fecCodec, err := fec.NewFEC(cfg.FECDataShards, cfg.FECParityShards, cfg.MTU/cfg.FECDataShards)
	if err != nil {
		return nil, fmt.Errorf("failed to create FEC: %v", err)
	}

	// Parse my tunnel IP
	myIP, err := parseTunnelIP(cfg.TunnelAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tunnel address: %v", err)
	}

	// Create encryption cipher if key is provided
	var cipher *crypto.Cipher
	if cfg.Key != "" {
		cipher, err = crypto.NewCipher(cfg.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to create encryption cipher: %v", err)
		}
		log.Println("Encryption enabled with AES-256-GCM")
	}

	t := &Tunnel{
		config:     cfg,
		fec:        fecCodec,
		cipher:     cipher,
		stopCh:     make(chan struct{}),
		myTunnelIP: myIP,
	}

	// Initialize P2P manager if enabled
	if cfg.P2PEnabled && cfg.Mode == "client" {
		t.p2pManager = p2p.NewManager(cfg.P2PPort)
		t.routingTable = routing.NewRoutingTable(cfg.MaxHops)
	}

	if cfg.Mode == "client" {
		t.sendQueue = make(chan []byte, cfg.SendQueueSize)
		t.recvQueue = make(chan []byte, cfg.RecvQueueSize)
	} else {
		// Server mode: multi-client support
		t.clients = make(map[string]*ClientConnection)
		// Server also needs routing table for mesh routing
		if cfg.EnableMeshRouting {
			t.routingTable = routing.NewRoutingTable(cfg.MaxHops)
		}
	}

	return t, nil
}

// parseTunnelIP extracts the IP address from tunnel address (e.g., "10.0.0.2/24" -> 10.0.0.2)
func parseTunnelIP(tunnelAddr string) (net.IP, error) {
	parts := strings.Split(tunnelAddr, "/")
	if len(parts) != 2 {
		return nil, errors.New("invalid tunnel address format, expected IP/mask")
	}

	// Validate IP address
	ip := net.ParseIP(parts[0])
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", parts[0])
	}

	// Validate CIDR mask (should be between 0 and 32 for IPv4)
	var maskBits int
	if _, err := fmt.Sscanf(parts[1], "%d", &maskBits); err != nil {
		return nil, fmt.Errorf("invalid CIDR mask: %s", parts[1])
	}
	if maskBits < 0 || maskBits > 32 {
		return nil, fmt.Errorf("CIDR mask must be between 0 and 32, got %d", maskBits)
	}

	return ip.To4(), nil
}

// Start starts the tunnel
func (t *Tunnel) Start() error {
	// Create TUN device
	// Use empty string to let kernel automatically assign device name (tun0, tun1, etc.)
	// This follows standard Linux TUN/TAP practices and prevents conflicts when multiple instances are running
	// The actual assigned device name is logged below and accessible via tunDev.Name()
	tunDev, err := CreateTUN("")
	if err != nil {
		return fmt.Errorf("failed to create TUN device: %v", err)
	}
	t.tunFile = tunDev
	t.tunName = tunDev.Name()

	log.Printf("Created TUN device: %s", t.tunName)

	// Configure TUN device
	if err := t.configureTUN(); err != nil {
		t.tunFile.Close()
		return fmt.Errorf("failed to configure TUN: %v", err)
	}

	// Establish connection based on mode
	if t.config.Mode == "client" {
		if err := t.connectClient(); err != nil {
			t.tunFile.Close()
			return fmt.Errorf("failed to connect as client: %v", err)
		}

		// Start P2P manager if enabled
		if t.config.P2PEnabled && t.p2pManager != nil {
			if err := t.p2pManager.Start(); err != nil {
				t.tunFile.Close()
				return fmt.Errorf("failed to start P2P manager: %v", err)
			}

			// Set packet handler for P2P
			t.p2pManager.SetPacketHandler(t.handleP2PPacket)

			log.Printf("P2P enabled on port %d", t.p2pManager.GetLocalPort())

			// Note: P2P info will be announced after receiving public address from server

			// Start route update goroutine
			t.wg.Add(1)
			go t.routeUpdateLoop()
		}

		// Start client mode packet processing
		t.wg.Add(4)
		go t.tunReader()
		go t.tunWriter()
		go t.netReader()
		go t.netWriter()

		// Start keepalive
		t.wg.Add(1)
		go t.keepalive()
	} else {
		// Server mode: start accepting clients
		if err := t.startServer(); err != nil {
			t.tunFile.Close()
			return fmt.Errorf("failed to start as server: %v", err)
		}
	}

	log.Printf("Tunnel started in %s mode", t.config.Mode)
	return nil
}

// Stop stops the tunnel
func (t *Tunnel) Stop() {
	// Use sync.Once to ensure Stop() logic only runs once
	t.stopOnce.Do(func() {
		// Close TUN device FIRST - this will unblock Read/Write operations
		if t.tunFile != nil {
			if err := t.tunFile.Close(); err != nil {
				log.Printf("Error closing TUN device: %v", err)
			}
		}

		// Close listener (server mode) - this will unblock Accept()
		if t.listener != nil {
			if err := t.listener.Close(); err != nil {
				log.Printf("Error closing listener: %v", err)
			}
		}

		// Close single connection (client mode) - this will unblock Read/Write
		if t.conn != nil {
			if err := t.conn.Close(); err != nil {
				log.Printf("Error closing connection: %v", err)
			}
		}

		// Signal all tunnel goroutines to stop
		close(t.stopCh)

		// Close all client connections and signal client goroutines (server mode)
		t.clientsMux.Lock()
		for _, client := range t.clients {
			// Use stopOnce to safely close both connection and channel
			client.stopOnce.Do(func() {
				// Close connection first
				if err := client.conn.Close(); err != nil {
					log.Printf("Error closing client connection: %v", err)
				}
				// Then signal client goroutines to stop
				close(client.stopCh)
			})
		}
		t.clientsMux.Unlock()

		// Stop P2P manager
		if t.p2pManager != nil {
			t.p2pManager.Stop()
		}

		// Now wait for all goroutines to finish
		// Now wait for all goroutines to finish, but avoid indefinite hang by
		// using a timeout. This prevents Stop() from blocking forever if some
		// goroutines do not exit due to unforeseen blocking operations.
		done := make(chan struct{})
		go func() {
			t.wg.Wait()
			close(done)
		}()
		select {
		case <-done:
			log.Println("Tunnel stopped")
		case <-time.After(5 * time.Second):
			log.Println("Timeout waiting for tunnel goroutines to stop; continuing shutdown")
		}
	})
}

// addClient adds a client to the routing table
func (t *Tunnel) addClient(client *ClientConnection, ip net.IP) {
	t.clientsMux.Lock()
	defer t.clientsMux.Unlock()

	ipStr := ip.String()
	if existing, ok := t.clients[ipStr]; ok {
		log.Printf("Warning: IP conflict detected for %s, closing old connection", ipStr)
		existing.stopOnce.Do(func() {
			// Close connection first to unblock I/O
			if err := existing.conn.Close(); err != nil {
				log.Printf("Error closing conflicting connection: %v", err)
			}
			// Then signal goroutines to stop
			close(existing.stopCh)
		})
	}

	client.clientIP = ip
	t.clients[ipStr] = client
	log.Printf("Client registered with IP: %s (total clients: %d)", ipStr, len(t.clients))
}

// removeClient removes a client from the routing table
func (t *Tunnel) removeClient(client *ClientConnection) {
	var clientIP net.IP

	t.clientsMux.Lock()
	if client.clientIP != nil {
		clientIP = client.clientIP
		ipStr := clientIP.String()
		delete(t.clients, ipStr)
		log.Printf("Client unregistered: %s (remaining clients: %d)", ipStr, len(t.clients))
	}
	t.clientsMux.Unlock()

	if clientIP != nil {
		// Remove from routing table if mesh routing enabled (outside of lock)
		if t.routingTable != nil {
			t.routingTable.RemovePeer(clientIP)
			log.Printf("Removed peer %s from routing table", clientIP)
		}

		// Broadcast peer disconnection to other clients (acquires its own lock)
		if t.config.P2PEnabled {
			t.broadcastPeerDisconnect(clientIP)
		}
	}
}

// broadcastPeerDisconnect notifies all clients that a peer has disconnected
func (t *Tunnel) broadcastPeerDisconnect(disconnectedIP net.IP) {
	// Format: DISCONNECT|TunnelIP
	disconnectInfo := fmt.Sprintf("DISCONNECT|%s", disconnectedIP.String())

	// Create peer info packet with disconnect message
	fullPacket := make([]byte, len(disconnectInfo)+1)
	fullPacket[0] = PacketTypePeerInfo
	copy(fullPacket[1:], []byte(disconnectInfo))

	// Encrypt
	encryptedPacket, err := t.encryptPacket(fullPacket)
	if err != nil {
		log.Printf("Failed to encrypt disconnect notification: %v", err)
		return
	}

	// Broadcast to all clients with its own lock
	t.clientsMux.RLock()
	defer t.clientsMux.RUnlock()

	for _, client := range t.clients {
		if client.clientIP != nil && !client.clientIP.Equal(disconnectedIP) {
			if err := client.conn.WritePacket(encryptedPacket); err != nil {
				log.Printf("Failed to send disconnect notification to %s: %v", client.clientIP, err)
			}
		}
	}
}

// getClientByIP retrieves a client by IP address
func (t *Tunnel) getClientByIP(ip net.IP) *ClientConnection {
	t.clientsMux.RLock()
	defer t.clientsMux.RUnlock()
	return t.clients[ip.String()]
}

// configureTUN configures the TUN device with IP address
func (t *Tunnel) configureTUN() error {
	// Parse tunnel address
	parts := strings.Split(t.config.TunnelAddr, "/")
	if len(parts) != 2 {
		return errors.New("invalid tunnel address format")
	}
	ip := parts[0]
	netmask := parts[1]

	// Set IP address
	cmd := exec.Command("ip", "addr", "add", t.config.TunnelAddr, "dev", t.tunName)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set IP: %v, output: %s", err, output)
	}

	// Bring interface up
	cmd = exec.Command("ip", "link", "set", "dev", t.tunName, "up")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to bring up interface: %v, output: %s", err, output)
	}

	// Set MTU
	cmd = exec.Command("ip", "link", "set", "dev", t.tunName, "mtu", fmt.Sprintf("%d", t.config.MTU))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to set MTU: %v, output: %s", err, output)
	}

	log.Printf("Configured %s with IP %s/%s, MTU %d", t.tunName, ip, netmask, t.config.MTU)
	return nil
}

// connectClient connects to server as client
func (t *Tunnel) connectClient() error {
	log.Printf("Connecting to server at %s...", t.config.RemoteAddr)

	timeout := time.Duration(t.config.Timeout) * time.Second

	log.Println("Using UDP with fake TCP headers for firewall bypass")
	conn, err := faketcp.Dial(t.config.RemoteAddr, timeout)
	if err != nil {
		return err
	}

	t.conn = conn
	log.Printf("Connected to server: %s -> %s", conn.LocalAddr(), conn.RemoteAddr())
	return nil
}

// reconnectToServer attempts to reconnect to the server with exponential backoff.
// It is safe to call from multiple goroutines; only one will perform the reconnect.
func (t *Tunnel) reconnectToServer() error {
	// Quick check: if tunnel is stopping, don't attempt reconnect
	select {
	case <-t.stopCh:
		return fmt.Errorf("tunnel stopping")
	default:
	}

	t.connMux.Lock()
	// If another goroutine already reconnected, use that connection
	if t.conn != nil {
		t.connMux.Unlock()
		return nil
	}

	defer t.connMux.Unlock()

	backoff := 1
	timeout := time.Duration(t.config.Timeout) * time.Second
	for {
		select {
		case <-t.stopCh:
			return fmt.Errorf("tunnel stopping")
		default:
		}

		log.Printf("Attempting to reconnect to server at %s (backoff %ds)", t.config.RemoteAddr, backoff)
		conn, err := faketcp.Dial(t.config.RemoteAddr, timeout)
		if err == nil {
			t.conn = conn
			log.Printf("Reconnected to server: %s -> %s", conn.LocalAddr(), conn.RemoteAddr())
			return nil
		}

		log.Printf("Reconnect attempt failed: %v", err)

		// Sleep with exponential backoff capped
		time.Sleep(time.Duration(backoff) * time.Second)
		backoff *= 2
		if backoff > 32 {
			backoff = 32
		}
	}
}

// startServer starts the server and accepts multiple clients
func (t *Tunnel) startServer() error {
	log.Printf("Listening on %s...", t.config.LocalAddr)

	log.Println("Using UDP with fake TCP headers for firewall bypass")
	listener, err := faketcp.Listen(t.config.LocalAddr)
	if err != nil {
		return err
	}

	// Store listener for later cleanup
	t.listener = listener

	// Start TUN reader for server mode
	t.wg.Add(1)
	go t.tunReaderServer()

	// Start accepting clients in a goroutine
	t.wg.Add(1)
	go t.acceptClients(listener)

	if t.config.MultiClient {
		log.Printf("Multi-client mode enabled (max: %d clients)", t.config.MaxClients)
		if t.config.ClientIsolation {
			log.Println("Client isolation enabled - clients cannot communicate with each other")
		}
	}

	return nil
}

// acceptClients accepts multiple client connections
func (t *Tunnel) acceptClients(listener *faketcp.Listener) {
	defer t.wg.Done()

	for {
		select {
		case <-t.stopCh:
			return
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-t.stopCh:
				// Tunnel is stopping, no need to log
			default:
				log.Printf("Accept error: %v", err)
			}
			return
		}

		// Check if we've reached max clients
		t.clientsMux.RLock()
		clientCount := len(t.clients)
		t.clientsMux.RUnlock()

		if !t.config.MultiClient && clientCount >= 1 {
			log.Printf("Single-client mode: rejecting connection from %s", conn.RemoteAddr())
			conn.Close()
			continue
		}

		if clientCount >= t.config.MaxClients {
			log.Printf("Max clients reached (%d), rejecting connection from %s", t.config.MaxClients, conn.RemoteAddr())
			conn.Close()
			continue
		}

		// Start handling this client
		go t.handleClient(conn)
	}
}

// handleClient handles a single client connection
func (t *Tunnel) handleClient(conn *faketcp.Conn) {
	log.Printf("Client connected: %s", conn.RemoteAddr())

	client := &ClientConnection{
		conn:      conn,
		sendQueue: make(chan []byte, t.config.SendQueueSize),
		recvQueue: make(chan []byte, t.config.RecvQueueSize),
		stopCh:    make(chan struct{}),
	}

	// Send client's public address for NAT traversal (if P2P enabled)
	if t.config.P2PEnabled {
		go t.sendPublicAddrToClient(client)
	}

	// Start client goroutines
	client.wg.Add(3)
	go t.clientNetReader(client)
	go t.clientNetWriter(client)
	go t.clientKeepalive(client)

	// Wait for client to disconnect
	client.wg.Wait()

	// Clean up client
	t.removeClient(client)
	log.Printf("Client disconnected: %s", conn.RemoteAddr())
}

// tunReader reads packets from TUN device and queues them for sending (client mode)
func (t *Tunnel) tunReader() {
	defer t.wg.Done()

	buf := make([]byte, t.config.MTU+100)

	for {
		select {
		case <-t.stopCh:
			return
		default:
		}

		n, err := t.tunFile.Read(buf)
		if err != nil {
			select {
			case <-t.stopCh:
				// Tunnel is stopping, no need to log
			default:
				log.Printf("TUN read error: %v", err)
			}
			return
		}

		if n > 0 {
			// Skip packets that are too small or not IPv4
			if n < IPv4MinHeaderLen {
				continue
			}

			// Check if packet is IPv4 (skip non-IPv4 packets like IPv6)
			if buf[0]>>4 != IPv4Version {
				continue
			}

			// Copy packet data
			packet := make([]byte, n)
			copy(packet, buf[:n])

			// Use intelligent routing if P2P is enabled
			if t.config.P2PEnabled && t.routingTable != nil {
				if err := t.sendPacketWithRouting(packet); err != nil {
					log.Printf("Failed to send packet: %v", err)
				}
			} else {
				// Default: queue for server
				select {
				case t.sendQueue <- packet:
				case <-t.stopCh:
					return
				default:
					log.Printf("Send queue full, dropping packet")
				}
			}
		}
	}
}

// tunReaderServer reads packets from TUN device and routes them to clients (server mode)
func (t *Tunnel) tunReaderServer() {
	defer t.wg.Done()

	buf := make([]byte, t.config.MTU+100)

	for {
		select {
		case <-t.stopCh:
			return
		default:
		}

		n, err := t.tunFile.Read(buf)
		if err != nil {
			select {
			case <-t.stopCh:
				// Tunnel is stopping, no need to log
			default:
				log.Printf("TUN read error: %v", err)
			}
			return
		}

		if n < IPv4MinHeaderLen {
			continue
		}

		// Copy packet data
		packet := make([]byte, n)
		copy(packet, buf[:n])

		// Parse destination IP from packet (IPv4)
		// IP header: version(4 bits) + IHL(4 bits) + ... + dst IP (4 bytes starting at offset 16 for IPv4)
		if packet[0]>>4 != IPv4Version {
			// Not IPv4, skip
			continue
		}

		dstIP := net.IP(packet[IPv4DstIPOffset : IPv4DstIPOffset+4])

		// Check if packet is destined for server itself
		// NOTE: This should rarely/never happen because packets destined for the server
		// come from client connections (via clientNetReader), not from the server's own TUN device.
		// Packets read from TUN are generated BY the server's OS going TO clients.
		// However, we keep this check for defensive programming.
		if dstIP.Equal(t.myTunnelIP) {
			log.Printf("WARNING: Unexpected packet from TUN destined for server itself (dstIP=%s). This might indicate a routing loop.", dstIP)
			// Drop the packet to prevent infinite loop
			continue
		}

		// Find the client with this destination IP
		client := t.getClientByIP(dstIP)
		if client != nil {
			select {
			case client.sendQueue <- packet:
			case <-t.stopCh:
				return
			default:
				log.Printf("Client send queue full for %s, dropping packet", dstIP)
			}
		}
		// If no client found, packet is dropped
	}
}

// tunWriter writes packets from receive queue to TUN device
func (t *Tunnel) tunWriter() {
	defer t.wg.Done()

	for {
		select {
		case <-t.stopCh:
			return
		case packet := <-t.recvQueue:
			if _, err := t.tunFile.Write(packet); err != nil {
				select {
				case <-t.stopCh:
					// Tunnel is stopping, no need to log
				default:
					log.Printf("TUN write error: %v", err)
				}
				return
			}
		}
	}
}

// netReader reads packets from network connection
func (t *Tunnel) netReader() {
	defer t.wg.Done()

	for {
		select {
		case <-t.stopCh:
			return
		default:
		}

		// Ensure we have a live connection
		if t.conn == nil {
			if err := t.reconnectToServer(); err != nil {
				// Tunnel stopping or cannot reconnect
				return
			}
		}

		packet, err := t.conn.ReadPacket()
		if err != nil {
			// Check if it's a timeout - if so, continue to allow checking stopCh
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}

			select {
			case <-t.stopCh:
				// Tunnel is stopping, no need to log
			default:
				log.Printf("Network read error: %v", err)
			}

			// Close and clear current connection, then attempt reconnect
			t.connMux.Lock()
			if t.conn != nil {
				_ = t.conn.Close()
				t.conn = nil
			}
			t.connMux.Unlock()

			if err := t.reconnectToServer(); err != nil {
				return
			}

			// Successfully reconnected, continue reading
			continue
		}

		if len(packet) < 1 {
			continue
		}

		// Decrypt if cipher is available
		decryptedPacket, err := t.decryptPacket(packet)
		if err != nil {
			log.Printf("Decryption error (wrong key?): %v", err)
			continue
		}

		if len(decryptedPacket) < 1 {
			continue
		}

		// Check packet type
		packetType := decryptedPacket[0]
		payload := decryptedPacket[1:]

		switch packetType {
		case PacketTypeData:
			// Queue for TUN device
			select {
			case t.recvQueue <- payload:
			case <-t.stopCh:
				return
			default:
				log.Printf("Receive queue full, dropping packet")
			}
		case PacketTypeKeepalive:
			// Keepalive received, no action needed
		case PacketTypePublicAddr:
			// Server sent us our public address
			publicAddr := string(payload)
			t.publicAddrMux.Lock()
			t.publicAddr = publicAddr
			t.publicAddrMux.Unlock()
			log.Printf("Received public address from server: %s", publicAddr)

			// Detect NAT type if enabled
			if t.config.EnableNATDetection && t.p2pManager != nil {
				go func() {
					// Perform NAT detection
					t.p2pManager.DetectNATType(t.config.RemoteAddr)
				}()
			}

			// Now announce P2P info with the correct public address
			if t.p2pManager != nil {
				// Wait a bit for NAT detection to complete before announcing
				time.Sleep(500 * time.Millisecond)
				
				// Retry announcement with exponential backoff if it fails
				go func() {
					retries := 0
					for retries < P2PMaxRetries {
						if err := t.announcePeerInfo(); err != nil {
							log.Printf("Failed to announce P2P info (attempt %d/%d): %v", retries+1, P2PMaxRetries, err)
							retries++
							// Exponential backoff with cap
							backoffSeconds := 1 << uint(retries)
							if backoffSeconds > P2PMaxBackoffSeconds {
								backoffSeconds = P2PMaxBackoffSeconds
							}
							time.Sleep(time.Duration(backoffSeconds) * time.Second)
						} else {
							log.Printf("Successfully announced P2P info")
							break
						}
					}
				}()
			}
		case PacketTypePeerInfo:
			// Received peer info from server about another client
			if t.config.P2PEnabled && t.p2pManager != nil {
				t.handlePeerInfoFromServer(payload)
			}
		case PacketTypePunch:
			// Server requests immediate simultaneous hole-punching
			if t.config.P2PEnabled && t.p2pManager != nil {
				t.handlePunchFromServer(payload)
			}
		}
	}
}

// netWriter writes packets from send queue to network connection
func (t *Tunnel) netWriter() {
	defer t.wg.Done()

	for {
		select {
		case <-t.stopCh:
			return
		case packet := <-t.sendQueue:
			// Prepend packet type
			fullPacket := make([]byte, len(packet)+1)
			fullPacket[0] = PacketTypeData
			copy(fullPacket[1:], packet)

			// Encrypt if cipher is available
			encryptedPacket, err := t.encryptPacket(fullPacket)
			if err != nil {
				log.Printf("Encryption error: %v", err)
				continue
			}

			// Ensure we have a live connection before writing
			if t.conn == nil {
				if err := t.reconnectToServer(); err != nil {
					return
				}
			}

			if err := t.conn.WritePacket(encryptedPacket); err != nil {
				select {
				case <-t.stopCh:
					// Tunnel is stopping, no need to log
				default:
					log.Printf("Network write error: %v", err)
				}

				// Close and clear connection then try to reconnect and retry once
				t.connMux.Lock()
				if t.conn != nil {
					_ = t.conn.Close()
					t.conn = nil
				}
				t.connMux.Unlock()

				if err := t.reconnectToServer(); err != nil {
					return
				}

				// Try writing once more after reconnect
				if t.conn != nil {
					if err2 := t.conn.WritePacket(encryptedPacket); err2 != nil {
						log.Printf("Network write retry failed: %v", err2)
						return
					}
				}
			}
		}
	}
}

// keepalive sends periodic keepalive packets
func (t *Tunnel) keepalive() {
	defer t.wg.Done()

	ticker := time.NewTicker(time.Duration(t.config.KeepaliveInterval) * time.Second)
	defer ticker.Stop()

	keepalivePacket := []byte{PacketTypeKeepalive}

	for {
		select {
		case <-t.stopCh:
			return
		case <-ticker.C:
			// Encrypt if cipher is available
			encryptedPacket, err := t.encryptPacket(keepalivePacket)
			if err != nil {
				log.Printf("Keepalive encryption error: %v", err)
				continue
			}
			// Ensure we have a live connection
			if t.conn == nil {
				if err := t.reconnectToServer(); err != nil {
					return
				}
			}

			if err := t.conn.WritePacket(encryptedPacket); err != nil {
				select {
				case <-t.stopCh:
					// Tunnel is stopping, no need to log
				default:
					log.Printf("Keepalive error: %v", err)
				}

				// Close and clear connection then attempt reconnect
				t.connMux.Lock()
				if t.conn != nil {
					_ = t.conn.Close()
					t.conn = nil
				}
				t.connMux.Unlock()

				if err := t.reconnectToServer(); err != nil {
					return
				}
				// don't return; let loop continue
			}
		}
	}
}

// clientNetReader reads packets from a client connection
func (t *Tunnel) clientNetReader(client *ClientConnection) {
	defer client.wg.Done()

	for {
		select {
		case <-t.stopCh:
			return
		case <-client.stopCh:
			return
		default:
		}

		packet, err := client.conn.ReadPacket()
		if err != nil {
			// Check if it's a timeout - if so, continue to allow checking stopCh
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-t.stopCh:
				// Tunnel is stopping, no need to log
			case <-client.stopCh:
				// Client already stopped, no need to log
			default:
				log.Printf("Client network read error from %s: %v", client.conn.RemoteAddr(), err)
			}
			client.stopOnce.Do(func() {
				close(client.stopCh)
			})
			return
		}

		if len(packet) < 1 {
			continue
		}

		// Decrypt if cipher is available
		decryptedPacket, err := t.decryptPacket(packet)
		if err != nil {
			log.Printf("Client decryption error from %s (wrong key?): %v", client.conn.RemoteAddr(), err)
			continue
		}

		if len(decryptedPacket) < 1 {
			continue
		}

		// Check packet type
		packetType := decryptedPacket[0]
		payload := decryptedPacket[1:]

		switch packetType {
		case PacketTypeData:
			if len(payload) < IPv4MinHeaderLen {
				continue
			}

			// Extract source IP from the packet to register client
			if payload[0]>>4 == IPv4Version { // IPv4
				srcIP := net.IP(payload[IPv4SrcIPOffset : IPv4SrcIPOffset+4])

				// Register client IP if not yet registered
				if client.clientIP == nil {
					t.addClient(client, srcIP)
				}

				// Route packet based on destination
				dstIP := net.IP(payload[IPv4DstIPOffset : IPv4DstIPOffset+4])

				// Check if destination is another client
				if t.config.ClientIsolation {
					// In isolation mode, only send to TUN device (server)
					// Clients cannot communicate with each other
					if _, err := t.tunFile.Write(payload); err != nil {
						select {
						case <-t.stopCh:
							// Tunnel is stopping, no need to log
						default:
							log.Printf("TUN write error: %v", err)
						}
						return
					}
				} else {
					// Check if packet is for another client
					targetClient := t.getClientByIP(dstIP)
					if targetClient != nil && targetClient != client {
						// Forward to target client (server relay mode)
						// This is expected when P2P is not yet established or when P2P fails
						select {
						case targetClient.sendQueue <- payload:
						case <-t.stopCh:
							return
						case <-client.stopCh:
							return
						default:
							log.Printf("Target client send queue full for %s, dropping packet", dstIP)
						}
					} else {
						// Send to TUN device (for server or unknown destination)
						if _, err := t.tunFile.Write(payload); err != nil {
							select {
							case <-t.stopCh:
								// Tunnel is stopping, no need to log
							default:
								log.Printf("TUN write error: %v", err)
							}
							return
						}
					}
				}
			}
		case PacketTypeKeepalive:
			// Keepalive received, no action needed
		case PacketTypePeerInfo:
			// Handle peer info from client (server mode)
			if t.config.P2PEnabled {
				peerInfoStr := string(payload)
				log.Printf("Received peer info from client: %s", peerInfoStr)

				// Parse peer info to get tunnel IP
				parts := strings.Split(peerInfoStr, "|")
				if len(parts) >= 3 {
					tunnelIP := net.ParseIP(parts[0])
					if tunnelIP != nil {
						// Register client if not yet registered
						if client.clientIP == nil {
							t.addClient(client, tunnelIP)
						}

						// Broadcast this peer info to all other clients
						// Save peerInfo on the client for later punch coordination (protected)
						client.mu.Lock()
						client.lastPeerInfo = peerInfoStr
						client.mu.Unlock()
						t.broadcastPeerInfo(tunnelIP, peerInfoStr)
					}
				}
			}
		}
	}
}

// clientNetWriter writes packets from client send queue to network
func (t *Tunnel) clientNetWriter(client *ClientConnection) {
	defer client.wg.Done()

	for {
		select {
		case <-t.stopCh:
			return
		case <-client.stopCh:
			return
		case packet := <-client.sendQueue:
			// Prepend packet type
			fullPacket := make([]byte, len(packet)+1)
			fullPacket[0] = PacketTypeData
			copy(fullPacket[1:], packet)

			// Encrypt if cipher is available
			encryptedPacket, err := t.encryptPacket(fullPacket)
			if err != nil {
				log.Printf("Client encryption error: %v", err)
				continue
			}

			if err := client.conn.WritePacket(encryptedPacket); err != nil {
				select {
				case <-t.stopCh:
					// Tunnel is stopping, no need to log
				case <-client.stopCh:
					// Client already stopped, no need to log
				default:
					log.Printf("Client network write error to %s: %v", client.conn.RemoteAddr(), err)
				}
				client.stopOnce.Do(func() {
					close(client.stopCh)
				})
				return
			}
		}
	}
}

// clientKeepalive sends periodic keepalive packets to a client
func (t *Tunnel) clientKeepalive(client *ClientConnection) {
	defer client.wg.Done()

	ticker := time.NewTicker(time.Duration(t.config.KeepaliveInterval) * time.Second)
	defer ticker.Stop()

	keepalivePacket := []byte{PacketTypeKeepalive}

	for {
		select {
		case <-t.stopCh:
			return
		case <-client.stopCh:
			return
		case <-ticker.C:
			// Encrypt if cipher is available
			encryptedPacket, err := t.encryptPacket(keepalivePacket)
			if err != nil {
				log.Printf("Client keepalive encryption error: %v", err)
				continue
			}
			if err := client.conn.WritePacket(encryptedPacket); err != nil {
				select {
				case <-t.stopCh:
					// Tunnel is stopping, no need to log
				case <-client.stopCh:
					// Client already stopped, no need to log
				default:
					log.Printf("Client keepalive error to %s: %v", client.conn.RemoteAddr(), err)
				}
				client.stopOnce.Do(func() {
					close(client.stopCh)
				})
				return
			}
		}
	}
}

// handleP2PPacket handles packets received via P2P connection
func (t *Tunnel) handleP2PPacket(peerIP net.IP, data []byte) {
	if len(data) < 1 {
		return
	}

	// Decrypt if cipher is available
	decryptedData, err := t.decryptPacket(data)
	if err != nil {
		log.Printf("P2P decryption error from %s (wrong key?): %v", peerIP, err)
		return
	}

	if len(decryptedData) < 1 {
		return
	}

	// Check packet type
	packetType := decryptedData[0]
	payload := decryptedData[1:]

	switch packetType {
	case PacketTypeData:
		// Queue for TUN device
		select {
		case t.recvQueue <- payload:
		case <-t.stopCh:
			return
		default:
			log.Printf("Receive queue full, dropping P2P packet from %s", peerIP)
		}
	case PacketTypePeerInfo:
		// Handle peer information advertisement
		t.handlePeerInfoPacket(peerIP, payload)
	case PacketTypeRouteInfo:
		// Handle route information
		t.handleRouteInfoPacket(peerIP, payload)
	}
}

// handlePeerInfoPacket handles peer information advertisements
func (t *Tunnel) handlePeerInfoPacket(fromIP net.IP, data []byte) {
	// Parse peer information from packet
	// Format: TunnelIP|PublicAddr|LocalAddr
	info := string(data)
	parts := strings.Split(info, "|")
	if len(parts) < 3 {
		return
	}

	tunnelIP := net.ParseIP(parts[0])
	if tunnelIP == nil {
		return
	}

	peer := p2p.NewPeerInfo(tunnelIP)
	peer.PublicAddr = parts[1]
	peer.LocalAddr = parts[2]

	// Add to routing table FIRST before P2P manager
	if t.routingTable != nil {
		t.routingTable.AddPeer(peer)
	}

	// Then add to P2P manager
	if t.p2pManager != nil {
		t.p2pManager.AddPeer(peer)
		// Try to establish P2P connection in a separate goroutine
		// Small delay to ensure peer is fully registered
		go func() {
			time.Sleep(P2PRegistrationDelay)
			t.p2pManager.ConnectToPeer(tunnelIP)
			// Update routes after P2P handshake attempt
			t.updateRoutesAfterP2PAttempt(tunnelIP, "peer advertisement")
		}()
	}

	log.Printf("Received peer info: %s at %s (local: %s)", tunnelIP, peer.PublicAddr, peer.LocalAddr)
}

// handlePeerInfoFromServer handles peer info received from server (client mode)
func (t *Tunnel) handlePeerInfoFromServer(data []byte) {
	// Parse peer information from packet
	// Format: TunnelIP|PublicAddr|LocalAddr|NATType (NAT type is optional for backward compatibility)
	info := string(data)
	parts := strings.Split(info, "|")
	if len(parts) < 2 {
		return
	}

	// Check if this is a disconnect message first
	if parts[0] == "DISCONNECT" {
		disconnectedIP := net.ParseIP(parts[1])
		if disconnectedIP != nil {
			t.handlePeerDisconnect(disconnectedIP)
		}
		return
	}

	// Normal peer info message requires at least 3 parts
	if len(parts) < 3 {
		return
	}

	tunnelIP := net.ParseIP(parts[0])
	if tunnelIP == nil {
		return
	}

	// Don't add ourselves
	if tunnelIP.Equal(t.myTunnelIP) {
		return
	}

	peer := p2p.NewPeerInfo(tunnelIP)
	peer.PublicAddr = parts[1]
	peer.LocalAddr = parts[2]

	// Parse NAT type if available (4th parameter)
	if len(parts) >= 4 {
		var natTypeNum int
		if _, err := fmt.Sscanf(parts[3], "%d", &natTypeNum); err == nil {
			peer.SetNATType(nat.NATType(natTypeNum))
			log.Printf("Peer %s has NAT type: %s", tunnelIP, peer.GetNATType())
		}
	}

	// Add to routing table FIRST before P2P manager
	if t.routingTable != nil {
		t.routingTable.AddPeer(peer)
	}

	// Then add to P2P manager
	if t.p2pManager != nil {
		t.p2pManager.AddPeer(peer)
		
		// Check if P2P is feasible based on NAT types
		canEstablishP2P := t.p2pManager.CanEstablishP2PWith(tunnelIP)

		// Determine who should initiate the P2P connection.
		// Primary: NAT level (lower is better). If equal, tie-break by
		// registered port (smaller port initiates to larger). If ports equal,
		// tie-break by tunnel IP last octet (smaller initiates to larger).
		shouldInitiate := false

		myNAT := t.p2pManager.GetNATType()
		peerNAT := peer.GetNATType()

		// If either NAT is unknown, default to initiating
		if myNAT == nat.NATUnknown || peerNAT == nat.NATUnknown {
			shouldInitiate = true
		} else if myNAT.GetLevel() != peerNAT.GetLevel() {
			// Different NAT levels: use existing logic (worse side initiates as implemented in NAT)
			shouldInitiate = myNAT.ShouldInitiateConnection(peerNAT)
		} else {
			// Equal NAT level: tie-break by ports then tunnel IP last byte
			myPort := t.p2pManager.GetLocalPort()
			peerPort := 0

			// Try to parse peer public address first, then local address
			if peer.PublicAddr != "" {
				if _, portStr, err := net.SplitHostPort(peer.PublicAddr); err == nil {
					if p, err := strconv.Atoi(portStr); err == nil {
						peerPort = p
					}
				}
			}
			if peerPort == 0 && peer.LocalAddr != "" {
				if _, portStr, err := net.SplitHostPort(peer.LocalAddr); err == nil {
					if p, err := strconv.Atoi(portStr); err == nil {
						peerPort = p
					}
				}
			}

			if peerPort != 0 {
				if myPort != peerPort {
					shouldInitiate = myPort < peerPort
				} else {
					// Ports equal: compare last octet of tunnel IPs (IPv4 expected)
					myIP4 := t.myTunnelIP.To4()
					peerIP4 := peer.TunnelIP.To4()
					if myIP4 != nil && peerIP4 != nil {
						shouldInitiate = myIP4[len(myIP4)-1] < peerIP4[len(peerIP4)-1]
					} else {
						// Fallback to manager decision
						shouldInitiate = t.p2pManager.ShouldInitiateConnectionToPeer(tunnelIP)
					}
				}
			} else {
				// Couldn't parse peer port; fallback to manager decision
				shouldInitiate = t.p2pManager.ShouldInitiateConnectionToPeer(tunnelIP)
			}
		}
		
		if !canEstablishP2P {
			log.Printf("P2P not feasible with %s (both Symmetric NAT), will use server relay", tunnelIP)
			// Still add to routing table but don't attempt P2P
			return
		}
		
		// Try to establish P2P connection in a separate goroutine
		// Only initiate if our NAT level is better (lower)
		if shouldInitiate {
			// Small delay to ensure peer is fully registered
			go func() {
				time.Sleep(P2PRegistrationDelay)
				t.p2pManager.ConnectToPeer(tunnelIP)
				// Update routes after P2P handshake attempt
				t.updateRoutesAfterP2PAttempt(tunnelIP, "server broadcast")
			}()
			log.Printf("Will initiate P2P connection to %s (NAT priority)", tunnelIP)
		} else {
			log.Printf("Waiting for %s to initiate P2P connection (NAT priority)", tunnelIP)
		}
	}

	log.Printf("Received peer info from server: %s at %s (local: %s)", tunnelIP, peer.PublicAddr, peer.LocalAddr)
}

// handlePunchFromServer handles a server-initiated punch control packet
func (t *Tunnel) handlePunchFromServer(data []byte) {
	// Parse peer information from packet
	// Format: TunnelIP|PublicAddr|LocalAddr|NATType (NAT type is optional)
	info := string(data)
	parts := strings.Split(info, "|")
	if len(parts) < 3 {
		return
	}

	tunnelIP := net.ParseIP(parts[0])
	if tunnelIP == nil {
		return
	}

	// Don't add ourselves
	if tunnelIP.Equal(t.myTunnelIP) {
		return
	}

	peer := p2p.NewPeerInfo(tunnelIP)
	peer.PublicAddr = parts[1]
	peer.LocalAddr = parts[2]

	// Parse NAT type if available (4th parameter)
	if len(parts) >= 4 {
		var natTypeNum int
		if _, err := fmt.Sscanf(parts[3], "%d", &natTypeNum); err == nil {
			peer.SetNATType(nat.NATType(natTypeNum))
		}
	}

	// Add to routing table first
	if t.routingTable != nil {
		t.routingTable.AddPeer(peer)
	}

	// Then add to P2P manager and immediately attempt connection (no delay for PUNCH)
	// PUNCH messages indicate both sides should attempt simultaneously
	if t.p2pManager != nil {
		t.p2pManager.AddPeer(peer)
		
		// Check if P2P is feasible
		if !t.p2pManager.CanEstablishP2PWith(tunnelIP) {
			log.Printf("PUNCH received for %s but P2P not feasible (both Symmetric NAT)", tunnelIP)
			return
		}
		
		go func() {
			t.p2pManager.ConnectToPeer(tunnelIP)
			// Update routes after P2P handshake attempt
			t.updateRoutesAfterP2PAttempt(tunnelIP, "PUNCH")
		}()
	}

	log.Printf("Received PUNCH from server for %s at %s (local: %s)", tunnelIP, peer.PublicAddr, peer.LocalAddr)
}

// handlePeerDisconnect handles notification that a peer has disconnected
func (t *Tunnel) handlePeerDisconnect(peerIP net.IP) {
	log.Printf("Peer %s disconnected, removing from routing table", peerIP)

	// Remove from routing table
	if t.routingTable != nil {
		t.routingTable.RemovePeer(peerIP)
	}

	// Remove from P2P manager
	if t.p2pManager != nil {
		t.p2pManager.RemovePeer(peerIP)
	}
}

// handleRouteInfoPacket handles route information updates
func (t *Tunnel) handleRouteInfoPacket(fromIP net.IP, data []byte) {
	// This can be extended to exchange routing information
	// For now, we rely on direct connectivity checks
}

// routeUpdateLoop periodically updates route quality and selects best routes
func (t *Tunnel) routeUpdateLoop() {
	defer t.wg.Done()

	ticker := time.NewTicker(time.Duration(t.config.RouteUpdateInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-t.stopCh:
			return
		case <-ticker.C:
			if t.routingTable != nil {
				// Update all routes based on current peer states
				t.routingTable.UpdateRoutes()

				// Clean stale routes
				t.routingTable.CleanStaleRoutes(60 * time.Second)

				// Log routing stats with more detail
				stats := t.routingTable.GetRouteStats()
				log.Printf("Routing stats: %d peers, %d direct, %d relay, %d server",
					stats["total_peers"], stats["direct_routes"],
					stats["relay_routes"], stats["server_routes"])

				// Log individual peer status for debugging
				peers := t.routingTable.GetAllPeers()
				for _, peer := range peers {
					route := t.routingTable.GetRoute(peer.TunnelIP)
					if route != nil {
						var routeTypeStr string
						switch route.Type {
						case routing.RouteDirect:
							routeTypeStr = "P2P-DIRECT"
						case routing.RouteRelay:
							routeTypeStr = "P2P-RELAY"
						case routing.RouteServer:
							routeTypeStr = "SERVER-RELAY"
						}

						connStatus := "disconnected"
						if peer.Connected {
							connStatus = "connected"
							if peer.IsLocalConnection {
								connStatus = "connected-local"
							}
						}

						log.Printf("  Peer %s: route=%s quality=%d status=%s throughServer=%v",
							peer.TunnelIP, routeTypeStr, route.Quality, connStatus, peer.ThroughServer)
					}
				}
			}
		}
	}
}

// sendPacketWithRouting sends a packet using intelligent routing
func (t *Tunnel) sendPacketWithRouting(packet []byte) error {
	if len(packet) < IPv4MinHeaderLen {
		return errors.New("packet too small")
	}

	// Parse destination IP
	if packet[0]>>4 != IPv4Version {
		return errors.New("not IPv4 packet")
	}

	dstIP := net.IP(packet[IPv4DstIPOffset : IPv4DstIPOffset+4])

	// Get best route
	if t.routingTable != nil {
		route := t.routingTable.GetRoute(dstIP)
		if route != nil {
			switch route.Type {
			case routing.RouteDirect:
				// Send via P2P
				if t.p2pManager != nil && t.p2pManager.IsConnected(dstIP) {
					fullPacket := make([]byte, len(packet)+1)
					fullPacket[0] = PacketTypeData
					copy(fullPacket[1:], packet)

					// Encrypt the packet before sending via P2P
					encryptedPacket, err := t.encryptPacket(fullPacket)
					if err != nil {
						log.Printf("P2P encryption error: %v", err)
						// Mark peer as going through server on encryption failure
						t.markPeerFallbackToServer(dstIP)
						return t.sendViaServer(packet)
					}

					if err := t.p2pManager.SendPacket(dstIP, encryptedPacket); err != nil {
						log.Printf("P2P send failed to %s, falling back to server: %v", dstIP, err)
						// Mark peer as going through server on send failure
						t.markPeerFallbackToServer(dstIP)
						// Fall back to server
						return t.sendViaServer(packet)
					}
					return nil
				}
				// P2P not connected despite direct route - update peer state
				t.markPeerFallbackToServer(dstIP)
				return t.sendViaServer(packet)
			case routing.RouteRelay:
				// Send via relay peer
				// For now, fall back to server (relay implementation can be added later)
				log.Printf("Relay routing not yet implemented, using server for %s", dstIP)
				return t.sendViaServer(packet)
			}
		}
	}

	// Default: send via server
	return t.sendViaServer(packet)
}

// sendViaServer sends packet through the server connection
func (t *Tunnel) sendViaServer(packet []byte) error {
	select {
	case t.sendQueue <- packet:
		return nil
	case <-t.stopCh:
		return errors.New("tunnel stopped")
	default:
		return errors.New("send queue full")
	}
}

// markPeerFallbackToServer updates routing state to force server relay for a peer.
func (t *Tunnel) markPeerFallbackToServer(dstIP net.IP) {
	if t.routingTable == nil || dstIP == nil {
		return
	}
	if peer := t.routingTable.GetPeer(dstIP); peer != nil {
		peer.SetConnected(false)
		peer.SetThroughServer(true)
		t.routingTable.UpdateRoutes()
	}
}

// updateRoutesAfterP2PAttempt waits for P2P handshake to complete and updates routes accordingly.
// This should be called in a goroutine after ConnectToPeer is initiated.
func (t *Tunnel) updateRoutesAfterP2PAttempt(tunnelIP net.IP, source string) {
	// Wait for P2P handshake to complete
	time.Sleep(P2PHandshakeWaitTime)
	
	if t.routingTable != nil {
		t.routingTable.UpdateRoutes()
		route := t.routingTable.GetRoute(tunnelIP)
		if route != nil && route.Type == routing.RouteDirect {
			log.Printf("✓ P2P direct route established to %s (via %s)", tunnelIP, source)
		} else {
			log.Printf("⚠ P2P connection to %s not established, will use server relay", tunnelIP)
		}
	}
}

// Helper to get local IP for the other peer
func GetPeerIP(tunnelAddr string) (string, error) {
	parts := strings.Split(tunnelAddr, "/")
	if len(parts) != 2 {
		return "", errors.New("invalid tunnel address")
	}

	ip := net.ParseIP(parts[0])
	if ip == nil {
		return "", errors.New("invalid IP address")
	}

	// Increment last octet for peer
	ip4 := ip.To4()
	if ip4 == nil {
		return "", errors.New("only IPv4 supported")
	}

	lastOctet := ip4[3]
	if lastOctet == 0 || lastOctet == 255 {
		return "", errors.New("tunnel address must not use 0 or 255 for peer derivation")
	}
	if lastOctet == 1 {
		ip4[3] = 2
	} else {
		ip4[3] = 1
	}

	return fmt.Sprintf("%s/%s", ip4.String(), parts[1]), nil
}

// encryptPacket encrypts a packet if cipher is available
func (t *Tunnel) encryptPacket(data []byte) ([]byte, error) {
	if t.cipher == nil {
		return data, nil
	}
	return t.cipher.Encrypt(data)
}

// decryptPacket decrypts a packet if cipher is available
func (t *Tunnel) decryptPacket(data []byte) ([]byte, error) {
	if t.cipher == nil {
		return data, nil
	}
	return t.cipher.Decrypt(data)
}

// announcePeerInfo sends peer information to server (client mode)
func (t *Tunnel) announcePeerInfo() error {
	if t.p2pManager == nil {
		return nil
	}

	// Get local P2P port
	p2pPort := t.p2pManager.GetLocalPort()

	// Get our public address (received from server)
	t.publicAddrMux.RLock()
	publicAddrStr := t.publicAddr
	t.publicAddrMux.RUnlock()

	if publicAddrStr == "" {
		// Public address not yet received from server, will try again later
		return fmt.Errorf("public address not yet available")
	}

	// Parse public address to extract IP
	publicHost, _, err := net.SplitHostPort(publicAddrStr)
	if err != nil {
		return fmt.Errorf("failed to parse public address: %v", err)
	}

	// Build P2P address with P2P port using public IP
	publicP2PAddr := fmt.Sprintf("%s:%d", publicHost, p2pPort)

	// Get local address for local network peers
	localAddr := t.conn.LocalAddr()
	if localAddr == nil {
		return fmt.Errorf("connection has no local address")
	}
	localAddrStr := localAddr.String()

	// Parse to extract local IP (format is "IP:port")
	localHost, _, err := net.SplitHostPort(localAddrStr)
	if err != nil {
		return fmt.Errorf("failed to parse local address: %v", err)
	}

	// Build local P2P address
	localP2PAddr := fmt.Sprintf("%s:%d", localHost, p2pPort)

	// Get NAT type
	natType := t.p2pManager.GetNATType()
	natTypeNum := int(natType)

	// Format: TunnelIP|PublicAddr|LocalAddr|NATType
	// Use public address for NAT traversal and local address for same-network peers
	// NAT type is included to enable smart P2P connection decisions
	peerInfo := fmt.Sprintf("%s|%s|%s|%d", t.myTunnelIP.String(), publicP2PAddr, localP2PAddr, natTypeNum)

	// Create peer info packet
	fullPacket := make([]byte, len(peerInfo)+1)
	fullPacket[0] = PacketTypePeerInfo
	copy(fullPacket[1:], []byte(peerInfo))

	// Encrypt
	encryptedPacket, err := t.encryptPacket(fullPacket)
	if err != nil {
		return fmt.Errorf("failed to encrypt peer info: %v", err)
	}

	// Send to server
	if err := t.conn.WritePacket(encryptedPacket); err != nil {
		return fmt.Errorf("failed to send peer info: %v", err)
	}

	log.Printf("Announced P2P info to server: %s at public=%s local=%s NAT=%s", 
		t.myTunnelIP, publicP2PAddr, localP2PAddr, natType)
	return nil
}

// sendPublicAddrToClient sends the client's public address for NAT traversal (server mode)
func (t *Tunnel) sendPublicAddrToClient(client *ClientConnection) {
	// Get client's public address from connection
	remoteAddr := client.conn.RemoteAddr()
	if remoteAddr == nil {
		log.Printf("Cannot send public address: client has no remote address")
		return
	}

	publicAddrStr := remoteAddr.String()

	// Create public address packet
	fullPacket := make([]byte, len(publicAddrStr)+1)
	fullPacket[0] = PacketTypePublicAddr
	copy(fullPacket[1:], []byte(publicAddrStr))

	// Encrypt the packet (don't rely on clientNetWriter since this is not a data packet)
	encryptedPacket, err := t.encryptPacket(fullPacket)
	if err != nil {
		log.Printf("Failed to encrypt public address: %v", err)
		return
	}

	// Send directly to network connection (bypass sendQueue which is for data packets)
	// This avoids double-wrapping by clientNetWriter
	if err := client.conn.WritePacket(encryptedPacket); err != nil {
		log.Printf("Failed to send public address to client: %v", err)
		// Signal client to disconnect on write error (consistent with clientNetWriter behavior)
		client.stopOnce.Do(func() {
			close(client.stopCh)
		})
		return
	}

	log.Printf("Sent public address %s to client", publicAddrStr)
}

// broadcastPeerInfo broadcasts peer information to all connected clients (server mode)
func (t *Tunnel) broadcastPeerInfo(newClientIP net.IP, peerInfo string) {
	if !t.config.P2PEnabled {
		return
	}

	// Create peer info packet
	fullPacket := make([]byte, len(peerInfo)+1)
	fullPacket[0] = PacketTypePeerInfo
	copy(fullPacket[1:], []byte(peerInfo))

	// Encrypt
	encryptedPacket, err := t.encryptPacket(fullPacket)
	if err != nil {
		log.Printf("Failed to encrypt peer info for broadcast: %v", err)
		return
	}

	// Broadcast to all clients except the sender and also send a PUNCH control to prompt simultaneous hole-punching
	t.clientsMux.RLock()
	defer t.clientsMux.RUnlock()
	for _, client := range t.clients {
		if client.clientIP != nil && !client.clientIP.Equal(newClientIP) {
			// Send peer info to existing client
			if err := client.conn.WritePacket(encryptedPacket); err != nil {
				log.Printf("Failed to broadcast peer info to %s: %v", client.clientIP, err)
				client.stopOnce.Do(func() { close(client.stopCh) })
			} else {
				log.Printf("Broadcasted peer info of %s to client %s", newClientIP, client.clientIP)
			}

			// Send PUNCH control to existing client so it will attempt punching to new client immediately
			punchPacket := make([]byte, len(peerInfo)+1)
			punchPacket[0] = PacketTypePunch
			copy(punchPacket[1:], []byte(peerInfo))
			encryptedPunch, err := t.encryptPacket(punchPacket)
			if err == nil {
				if err := client.conn.WritePacket(encryptedPunch); err != nil {
					log.Printf("Failed to send PUNCH to %s: %v", client.clientIP, err)
				} else {
					log.Printf("Sent PUNCH for %s to client %s", newClientIP, client.clientIP)
				}
			} else {
				log.Printf("Failed to encrypt PUNCH packet: %v", err)
			}

			// Also send existing client's peerInfo as a PUNCH to the new client so new client will punch back
			client.mu.RLock()
			clientInfo := client.lastPeerInfo
			client.mu.RUnlock()
			if clientInfo != "" {
				punchBack := make([]byte, len(clientInfo)+1)
				punchBack[0] = PacketTypePunch
				copy(punchBack[1:], []byte(clientInfo))
				encryptedPunchBack, err := t.encryptPacket(punchBack)
				if err == nil {
					// Need to send to the new client's connection; find it by IP
					if newClient := t.getClientByIP(newClientIP); newClient != nil {
						if err := newClient.conn.WritePacket(encryptedPunchBack); err != nil {
							log.Printf("Failed to send PUNCH back to new client %s: %v", newClientIP, err)
						} else {
							log.Printf("Sent PUNCH (existing %s) to new client %s", client.clientIP, newClientIP)
						}
					}
				} else {
					log.Printf("Failed to encrypt PUNCH back packet: %v", err)
				}
			}
		}
	}
}
