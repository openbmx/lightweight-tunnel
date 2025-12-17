package tunnel

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/openbmx/lightweight-tunnel/internal/config"
	"github.com/openbmx/lightweight-tunnel/pkg/fec"
	"github.com/openbmx/lightweight-tunnel/pkg/p2p"
	"github.com/openbmx/lightweight-tunnel/pkg/routing"
	"github.com/openbmx/lightweight-tunnel/pkg/tcp_disguise"
)

const (
	PacketTypeData      = 0x01
	PacketTypeKeepalive = 0x02
	PacketTypePeerInfo  = 0x03 // Peer discovery/advertisement
	PacketTypeRouteInfo = 0x04 // Route information exchange

	// IPv4 constants
	IPv4Version      = 4
	IPv4SrcIPOffset  = 12
	IPv4DstIPOffset  = 16
	IPv4MinHeaderLen = 20
)

// ClientConnection represents a single client connection
type ClientConnection struct {
	conn       *tcp_disguise.Conn
	sendQueue  chan []byte
	recvQueue  chan []byte
	clientIP   net.IP
	stopCh     chan struct{}
	stopOnce   sync.Once
	wg         sync.WaitGroup
}

// Tunnel represents a lightweight tunnel
type Tunnel struct {
	config     *config.Config
	fec        *fec.FEC
	conn       *tcp_disguise.Conn    // Used in client mode
	clients    map[string]*ClientConnection // Used in server mode (key: IP address)
	clientsMux sync.RWMutex
	tunName    string
	tunFile    *TunDevice
	stopCh     chan struct{}
	wg         sync.WaitGroup
	sendQueue  chan []byte  // Used in client mode
	recvQueue  chan []byte  // Used in client mode
	
	// P2P and routing
	p2pManager    *p2p.Manager      // P2P connection manager
	routingTable  *routing.RoutingTable // Routing table
	myTunnelIP    net.IP            // My tunnel IP address
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

	t := &Tunnel{
		config:     cfg,
		fec:        fecCodec,
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
		return nil, errors.New("invalid tunnel address format")
	}
	ip := net.ParseIP(parts[0])
	if ip == nil {
		return nil, errors.New("invalid IP address")
	}
	return ip.To4(), nil
}

// Start starts the tunnel
func (t *Tunnel) Start() error {
	// Create TUN device
	tunDev, err := CreateTUN("tun0")
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
	close(t.stopCh)
	
	// Stop P2P manager
	if t.p2pManager != nil {
		t.p2pManager.Stop()
	}
	
	// Close all client connections (server mode)
	t.clientsMux.Lock()
	for _, client := range t.clients {
		client.stopOnce.Do(func() {
			close(client.stopCh)
		})
		client.conn.Close()
	}
	t.clientsMux.Unlock()
	
	// Close single connection (client mode)
	if t.conn != nil {
		t.conn.Close()
	}
	
	if t.tunFile != nil {
		t.tunFile.Close()
	}
	t.wg.Wait()
	log.Println("Tunnel stopped")
}

// addClient adds a client to the routing table
func (t *Tunnel) addClient(client *ClientConnection, ip net.IP) {
	t.clientsMux.Lock()
	defer t.clientsMux.Unlock()

	ipStr := ip.String()
	if existing, ok := t.clients[ipStr]; ok {
		log.Printf("Warning: IP conflict detected for %s, closing old connection", ipStr)
		existing.stopOnce.Do(func() {
			close(existing.stopCh)
		})
		existing.conn.Close()
	}

	client.clientIP = ip
	t.clients[ipStr] = client
	log.Printf("Client registered with IP: %s (total clients: %d)", ipStr, len(t.clients))
}

// removeClient removes a client from the routing table
func (t *Tunnel) removeClient(client *ClientConnection) {
	t.clientsMux.Lock()
	defer t.clientsMux.Unlock()

	if client.clientIP != nil {
		ipStr := client.clientIP.String()
		delete(t.clients, ipStr)
		log.Printf("Client unregistered: %s (remaining clients: %d)", ipStr, len(t.clients))
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
	
	var conn *tcp_disguise.Conn
	var err error
	
	if t.config.TLSEnabled {
		log.Println("TLS encryption enabled")
		tlsConfig := &tls.Config{
			InsecureSkipVerify: t.config.TLSSkipVerify,
			MinVersion:         tls.VersionTLS12,
		}
		
		if t.config.TLSSkipVerify {
			log.Println("WARNING: TLS certificate verification disabled (insecure)")
		}
		
		conn, err = tcp_disguise.DialTLS(t.config.RemoteAddr, timeout, tlsConfig)
	} else {
		log.Println("WARNING: TLS encryption disabled - traffic is sent in plaintext and can be inspected by ISPs")
		conn, err = tcp_disguise.DialTCP(t.config.RemoteAddr, timeout)
	}
	
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
	
	var listener *tcp_disguise.Listener
	var err error
	
	if t.config.TLSEnabled {
		log.Println("TLS encryption enabled")
		
		if t.config.TLSCertFile == "" || t.config.TLSKeyFile == "" {
			return errors.New("TLS enabled but tls_cert_file or tls_key_file not specified in configuration")
		}
		
		cert, err := tls.LoadX509KeyPair(t.config.TLSCertFile, t.config.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("failed to load TLS certificate: %v", err)
		}
		
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		
		listener, err = tcp_disguise.ListenTLS(t.config.LocalAddr, tlsConfig)
	} else {
		log.Println("WARNING: TLS encryption disabled - traffic is sent in plaintext and can be inspected by ISPs")
		listener, err = tcp_disguise.ListenTCP(t.config.LocalAddr)
	}
	
	if err != nil {
		return err
	}

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
func (t *Tunnel) acceptClients(listener *tcp_disguise.Listener) {
	defer t.wg.Done()
	defer listener.Close()

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
func (t *Tunnel) handleClient(conn *tcp_disguise.Conn) {
	log.Printf("Client connected: %s", conn.RemoteAddr())

	client := &ClientConnection{
		conn:      conn,
		sendQueue: make(chan []byte, t.config.SendQueueSize),
		recvQueue: make(chan []byte, t.config.RecvQueueSize),
		stopCh:    make(chan struct{}),
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

		// Check packet type
		packetType := packet[0]
		payload := packet[1:]

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

			if err := t.conn.WritePacket(fullPacket); err != nil {
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
			if err := t.conn.WritePacket(keepalivePacket); err != nil {
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

		// Check packet type
		packetType := packet[0]
		payload := packet[1:]

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

			if err := client.conn.WritePacket(fullPacket); err != nil {
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
			if err := client.conn.WritePacket(keepalivePacket); err != nil {
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
	
	// Check packet type
	packetType := data[0]
	payload := data[1:]
	
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
	
	// Add to P2P manager
	if t.p2pManager != nil {
		t.p2pManager.AddPeer(peer)
		
		// Try to establish P2P connection
		go t.p2pManager.ConnectToPeer(tunnelIP)
	}
	
	// Add to routing table
	if t.routingTable != nil {
		t.routingTable.AddPeer(peer)
	}
	
	log.Printf("Received peer info: %s at %s", tunnelIP, peer.PublicAddr)
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
					
					if err := t.p2pManager.SendPacket(dstIP, fullPacket); err != nil {
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
