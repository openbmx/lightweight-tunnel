package tunnel

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/openbmx/lightweight-tunnel/internal/config"
	"github.com/openbmx/lightweight-tunnel/pkg/crypto"
	"github.com/openbmx/lightweight-tunnel/pkg/faketcp"
	"github.com/openbmx/lightweight-tunnel/pkg/fec"
	"github.com/openbmx/lightweight-tunnel/pkg/p2p"
	"github.com/openbmx/lightweight-tunnel/pkg/routing"
)

const (
	PacketTypeData       = 0x01
	PacketTypeKeepalive  = 0x02
	PacketTypePeerInfo   = 0x03 // Peer discovery/advertisement
	PacketTypeRouteInfo  = 0x04 // Route information exchange
	PacketTypePublicAddr = 0x05 // Server tells client its public address

	// IPv4 constants
	IPv4Version      = 4
	IPv4SrcIPOffset  = 12
	IPv4DstIPOffset  = 16
	IPv4MinHeaderLen = 20

	// P2P timing constants
	P2PRegistrationDelay = 100 * time.Millisecond // Delay to ensure peer registration completes
	P2PMaxRetries        = 5
	P2PMaxBackoffSeconds = 32 // Maximum backoff delay in seconds
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
}

// Tunnel represents a lightweight tunnel
type Tunnel struct {
	config       *config.Config
	fec          *fec.FEC
	cipher       *crypto.Cipher               // Encryption cipher (nil if no key)
	conn         *faketcp.Conn                // Used in client mode
	listener     *faketcp.Listener            // Used in server mode
	clients      map[string]*ClientConnection // Used in server mode (key: IP address)
	clientsMux   sync.RWMutex
	routeMux     sync.RWMutex
	clientRoutes map[string][]*net.IPNet // Advertised routes from clients (server mode)
	tunName      string
	tunFile      *TunDevice
	stopCh       chan struct{}
	stopOnce     sync.Once // Ensures Stop() is only executed once
	wg           sync.WaitGroup
	sendQueue    chan []byte // Used in client mode
	recvQueue    chan []byte // Used in client mode

	// P2P and routing
	p2pManager    *p2p.Manager          // P2P connection manager
	routingTable  *routing.RoutingTable // Routing table
	myTunnelIP    net.IP                // My tunnel IP address
	publicAddr    string                // Public address as seen by server (for NAT traversal)
	publicAddrMux sync.RWMutex          // Protects publicAddr
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
		t.clientRoutes = make(map[string][]*net.IPNet)
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
	tunDev, err := CreateTUN(t.config.TunName)
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

		// Advertise additional reachable routes to server
		if len(t.config.AdvertisedRoutes) > 0 {
			go t.announceRoutes()
		}
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
		t.wg.Wait()
		log.Println("Tunnel stopped")
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
		t.removeClientRoutes(existing.clientIP)
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

		// Remove advertised routes for this client
		t.removeClientRoutes(clientIP)

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

// getClientForDestination returns a client either by direct IP match or by advertised routes
func (t *Tunnel) getClientForDestination(dstIP net.IP) *ClientConnection {
	// Direct IP match first
	if client := t.getClientByIP(dstIP); client != nil {
		return client
	}

	// Route-based match
	t.routeMux.RLock()
	bestClientIP := chooseRouteClient(dstIP, t.clientRoutes)
	t.routeMux.RUnlock()

	if bestClientIP == "" {
		return nil
	}

	// Lookup client directly by stored key
	t.clientsMux.RLock()
	client := t.clients[bestClientIP]
	t.clientsMux.RUnlock()
	return client
}

// updateClientRoutes stores advertised routes for a client (server mode)
func (t *Tunnel) updateClientRoutes(clientIP net.IP, routes []string) {
	valid, invalid := parseCIDRList(routes)
	if len(invalid) > 0 {
		log.Printf("Ignoring invalid advertised routes from %s: %v", clientIP, invalid)
	}

	t.routeMux.Lock()
	if len(valid) == 0 {
		delete(t.clientRoutes, clientIP.String())
		t.routeMux.Unlock()
		return
	}
	t.clientRoutes[clientIP.String()] = valid
	t.routeMux.Unlock()
	log.Printf("Registered %d advertised route(s) for client %s", len(valid), clientIP)
}

// removeClientRoutes removes all advertised routes for a client
func (t *Tunnel) removeClientRoutes(clientIP net.IP) {
	if clientIP == nil {
		return
	}
	t.routeMux.Lock()
	delete(t.clientRoutes, clientIP.String())
	t.routeMux.Unlock()
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

	// TLS is not supported with UDP-based fake TCP
	if t.config.TLSEnabled {
		return fmt.Errorf("TLS is not supported with UDP-based fake TCP tunnel. For encryption, use IPsec, WireGuard, or application-level encryption")
	}

	log.Println("Using UDP with fake TCP headers for firewall bypass")
	conn, err := faketcp.Dial(t.config.RemoteAddr, timeout)
	if err != nil {
		return err
	}

	t.conn = conn
	log.Printf("Connected to server: %s -> %s", conn.LocalAddr(), conn.RemoteAddr())
	return nil
}

// startServer starts the server and accepts multiple clients
func (t *Tunnel) startServer() error {
	log.Printf("Listening on %s...", t.config.LocalAddr)

	// TLS is not supported with UDP-based fake TCP
	if t.config.TLSEnabled {
		return fmt.Errorf("TLS is not supported with UDP-based fake TCP tunnel. For encryption, use IPsec, WireGuard, or application-level encryption")
	}

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

		// Find the client with this destination IP (direct IP or advertised route)
		client := t.getClientForDestination(dstIP)
		if client != nil {
			select {
			case client.sendQueue <- packet:
			case <-t.stopCh:
				return
			default:
				log.Printf("Client send queue full for %s, dropping packet", dstIP)
			}
		}
		// If no client found, packet is dropped (or could be for server itself)
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
			return
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

			// Now announce P2P info with the correct public address
			if t.p2pManager != nil {
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

			if err := t.conn.WritePacket(encryptedPacket); err != nil {
				select {
				case <-t.stopCh:
					// Tunnel is stopping, no need to log
				default:
					log.Printf("Network write error: %v", err)
				}
				return
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
			if err := t.conn.WritePacket(encryptedPacket); err != nil {
				select {
				case <-t.stopCh:
					// Tunnel is stopping, no need to log
				default:
					log.Printf("Keepalive error: %v", err)
				}
				return
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
					targetClient := t.getClientForDestination(dstIP)
					if targetClient != nil && targetClient != client {
						// Forward to target client
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
						t.broadcastPeerInfo(tunnelIP, peerInfoStr)
					}
				}
			}
		case PacketTypeRouteInfo:
			tunnelIP, routes := parseRouteInfoPayload(payload)
			if tunnelIP == nil {
				continue
			}
			// Register client if not yet registered
			if client.clientIP == nil {
				t.addClient(client, tunnelIP)
			} else if !client.clientIP.Equal(tunnelIP) {
				log.Printf("Route info IP %s does not match registered client IP %s", tunnelIP, client.clientIP)
				continue
			}
			t.updateClientRoutes(tunnelIP, routes)
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
		}()
	}

	log.Printf("Received peer info: %s at %s (local: %s)", tunnelIP, peer.PublicAddr, peer.LocalAddr)
}

// handlePeerInfoFromServer handles peer info received from server (client mode)
func (t *Tunnel) handlePeerInfoFromServer(data []byte) {
	// Parse peer information from packet
	// Format: TunnelIP|PublicAddr|LocalAddr
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
		}()
	}

	log.Printf("Received peer info from server: %s at %s (local: %s)", tunnelIP, peer.PublicAddr, peer.LocalAddr)
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
	tunnelIP, routes := parseRouteInfoPayload(data)
	if tunnelIP == nil {
		log.Printf("Invalid route info packet from %s", fromIP)
		return
	}

	// Route advertisement over P2P is not applied to routing tables yet,
	// but we log it for visibility and future extension.
	log.Printf("Received route info via P2P from %s (%s): %v (not applied; server-side advertisements are supported)", fromIP, tunnelIP, routes)
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

				// Log routing stats
				stats := t.routingTable.GetRouteStats()
				log.Printf("Routing stats: %d peers, %d direct, %d relay, %d server",
					stats["total_peers"], stats["direct_routes"],
					stats["relay_routes"], stats["server_routes"])
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
						return t.sendViaServer(packet)
					}

					if err := t.p2pManager.SendPacket(dstIP, encryptedPacket); err != nil {
						log.Printf("P2P send failed to %s, falling back to server: %v", dstIP, err)
						// Fall back to server
						return t.sendViaServer(packet)
					}
					return nil
				}
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

	// Format: TunnelIP|PublicAddr|LocalAddr
	// Use public address for NAT traversal and local address for same-network peers
	peerInfo := fmt.Sprintf("%s|%s|%s", t.myTunnelIP.String(), publicP2PAddr, localP2PAddr)

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

	log.Printf("Announced P2P info to server: %s at public=%s local=%s", t.myTunnelIP, publicP2PAddr, localP2PAddr)
	return nil
}

// announceRoutes advertises additional reachable CIDR ranges to the server
func (t *Tunnel) announceRoutes() {
	if len(t.config.AdvertisedRoutes) == 0 || t.conn == nil {
		return
	}

	valid, invalid := parseCIDRList(t.config.AdvertisedRoutes)
	if len(invalid) > 0 {
		log.Printf("Skipping invalid advertised routes: %v", invalid)
	}
	if len(valid) == 0 {
		return
	}

	routeStrings := make([]string, 0, len(valid))
	for _, n := range valid {
		routeStrings = append(routeStrings, n.String())
	}

	payloadStr := fmt.Sprintf("%s|%s", t.myTunnelIP.String(), strings.Join(routeStrings, ","))
	fullPacket := make([]byte, len(payloadStr)+1)
	fullPacket[0] = PacketTypeRouteInfo
	copy(fullPacket[1:], []byte(payloadStr))

	encryptedPacket, err := t.encryptPacket(fullPacket)
	if err != nil {
		log.Printf("Failed to encrypt route announcement: %v", err)
		return
	}

	if err := t.conn.WritePacket(encryptedPacket); err != nil {
		log.Printf("Failed to send route announcement: %v", err)
	}
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

	// Broadcast to all clients except the sender
	t.clientsMux.RLock()
	defer t.clientsMux.RUnlock()
	for _, client := range t.clients {
		if client.clientIP != nil && !client.clientIP.Equal(newClientIP) {
			// Send directly to network connection (bypass sendQueue which is for data packets)
			// This avoids double-wrapping by clientNetWriter
			if err := client.conn.WritePacket(encryptedPacket); err != nil {
				log.Printf("Failed to broadcast peer info to %s: %v", client.clientIP, err)
				// Signal this specific client to disconnect on write error
				client.stopOnce.Do(func() {
					close(client.stopCh)
				})
			} else {
				log.Printf("Broadcasted peer info of %s to client %s", newClientIP, client.clientIP)
			}
		}
	}
}
