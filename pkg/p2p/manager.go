package p2p

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/openbmx/lightweight-tunnel/pkg/nat"
)

const (
	// HandshakeAttempts is the number of handshake packets to send
	HandshakeAttempts = 5
	// HandshakeInterval is the delay between handshake packets
	HandshakeInterval = 200 * time.Millisecond
	// ReadTimeout is the timeout for UDP read operations
	ReadTimeout = 1 * time.Second
	// LocalConnectionTimeout is the timeout to wait for local connection before trying public
	LocalConnectionTimeout = 2 * time.Second
)

// Connection represents a P2P UDP connection to a peer
type Connection struct {
	LocalAddr       *net.UDPAddr
	RemoteAddr      *net.UDPAddr
	Conn            *net.UDPConn
	PeerIP          net.IP // Tunnel IP of the peer
	IsLocalNetwork  bool   // Whether this connection is via local network
	sendQueue       chan []byte
	stopCh          chan struct{}
	wg              sync.WaitGroup
}

// Manager manages P2P connections
type Manager struct {
	localPort   int
	connections map[string]*Connection // Key: peer tunnel IP string
	listener    *net.UDPConn
	peers       map[string]*PeerInfo // Peer information
	mu          sync.RWMutex
	stopCh      chan struct{}
	wg          sync.WaitGroup
	onPacket    func(peerIP net.IP, data []byte) // Callback for received packets
	natDetector *nat.Detector // NAT type detector
	myNATType   nat.NATType   // My NAT type
	natTypeMux  sync.RWMutex  // Protects myNATType
}

// NewManager creates a new P2P connection manager
func NewManager(port int) *Manager {
	return &Manager{
		localPort:   port,
		connections: make(map[string]*Connection),
		peers:       make(map[string]*PeerInfo),
		stopCh:      make(chan struct{}),
		natDetector: nat.NewDetector(port, 5*time.Second),
		myNATType:   nat.NATUnknown,
	}
}

// Start starts the P2P manager
func (m *Manager) Start() error {
	// Listen on UDP port
	addr := &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: m.localPort,
	}
	
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %v", err)
	}
	
	m.listener = conn
	
	// Get actual port if auto-assigned
	if m.localPort == 0 {
		m.localPort = conn.LocalAddr().(*net.UDPAddr).Port
	}
	
	log.Printf("P2P manager listening on UDP port %d", m.localPort)
	
	// Start packet receiver
	m.wg.Add(1)
	go m.receivePackets()
	
	return nil
}

// Stop stops the P2P manager
func (m *Manager) Stop() {
	close(m.stopCh)

	if m.listener != nil {
		m.listener.Close()
	}

	m.mu.Lock()
	for _, conn := range m.connections {
		close(conn.stopCh)
		if conn.Conn != nil {
			conn.Conn.Close()
		}
	}
	m.mu.Unlock()

	// Wait for receivePackets goroutine to finish, but don't block forever
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return
	case <-time.After(5 * time.Second):
		log.Println("Timeout waiting for P2P manager goroutines to stop; continuing shutdown")
		return
	}
}

// SetPacketHandler sets the callback for received packets
func (m *Manager) SetPacketHandler(handler func(peerIP net.IP, data []byte)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onPacket = handler
}

// AddPeer adds peer information for P2P connection
func (m *Manager) AddPeer(peer *PeerInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	ipStr := peer.TunnelIP.String()
	m.peers[ipStr] = peer
	
	log.Printf("Added P2P peer: %s (public: %s, local: %s)", ipStr, peer.PublicAddr, peer.LocalAddr)
}

// ConnectToPeer establishes a P2P connection to a peer
// Priority order: 1) Local network address, 2) Public address, 3) Server fallback
// Smart strategy: Lower-level NAT connects to higher-level NAT for better stability
func (m *Manager) ConnectToPeer(peerTunnelIP net.IP) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	ipStr := peerTunnelIP.String()
	
	// Check if already connected
	if _, exists := m.connections[ipStr]; exists {
		// Check if peer is actually marked as connected
		if m.isPeerConnected(ipStr) {
			log.Printf("Already connected to peer %s", ipStr)
			return nil
		}
		// Reuse existing connection for retry
		log.Printf("Retrying P2P connection to %s", ipStr)
	}
	
	peer, exists := m.peers[ipStr]
	if !exists {
		return fmt.Errorf("peer %s not found", ipStr)
	}
	
	// Check if P2P is feasible based on NAT types
	myNATType := m.GetNATType()
	peerNATType := peer.GetNATType()
	
	// If both are symmetric NAT, skip P2P attempt and use server relay
	if myNATType == nat.NATSymmetric && peerNATType == nat.NATSymmetric {
		log.Printf("Both peers have Symmetric NAT (%s and %s) - skipping P2P, will use server relay",
			ipStr, peerTunnelIP)
		return fmt.Errorf("symmetric NAT detected on both sides, P2P not feasible")
	}
	
	// Check if we should initiate based on NAT levels
	// This is for logging/debugging; actual initiation is controlled by server coordination
	shouldInitiate := myNATType.ShouldInitiateConnection(peerNATType)
	if shouldInitiate {
		log.Printf("NAT level indicates we should initiate to %s (Our NAT: %s level %d, Peer NAT: %s level %d)",
			ipStr, myNATType, myNATType.GetLevel(), peerNATType, peerNATType.GetLevel())
	}
	
	// Priority: Try local address first (internal network direct connection)
	// Only fall back to public address if local fails
	hasLocalAddr := peer.LocalAddr != "" && peer.LocalAddr != peer.PublicAddr
	
	if hasLocalAddr {
		localAddr, err := net.ResolveUDPAddr("udp4", peer.LocalAddr)
		if err == nil {
			// Create connection object with local address (highest priority)
			conn := &Connection{
				RemoteAddr:     localAddr,
				PeerIP:         peerTunnelIP,
				IsLocalNetwork: true,
				sendQueue:      make(chan []byte, 100),
				stopCh:         make(chan struct{}),
			}
			m.connections[ipStr] = conn
			
			log.Printf("Attempting P2P connection to %s via LOCAL address first: %s (public: %s)", 
				ipStr, peer.LocalAddr, peer.PublicAddr)
			
			// Start local handshake first
			go m.performHandshakeWithFallback(conn, peer)
			return nil
		}
	}
	
	// No local address available, try public address directly
	remoteAddr, err := net.ResolveUDPAddr("udp4", peer.PublicAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve peer public address: %v", err)
	}
	
	// Create connection with public address
	conn := &Connection{
		RemoteAddr:     remoteAddr,
		PeerIP:         peerTunnelIP,
		IsLocalNetwork: false,
		sendQueue:      make(chan []byte, 100),
		stopCh:         make(chan struct{}),
	}
	m.connections[ipStr] = conn
	
	log.Printf("Attempting P2P connection to %s at public address: %s", ipStr, peer.PublicAddr)
	
	// Perform handshake to public address
	go m.performHandshake(conn, false)
	
	return nil
}

// performHandshakeWithFallback tries local address first, then falls back to public address
func (m *Manager) performHandshakeWithFallback(conn *Connection, peer *PeerInfo) {
	ipStr := conn.PeerIP.String()
	
	// First: Try local address with timeout
	log.Printf("P2P: Trying local address %s for peer %s", conn.RemoteAddr, ipStr)
	
	localSuccess := m.tryHandshakeWithTimeout(conn, LocalConnectionTimeout)
	
	if localSuccess {
		log.Printf("P2P: Local connection SUCCEEDED to %s via %s", ipStr, conn.RemoteAddr)
		return
	}
	
	log.Printf("P2P: Local connection to %s failed, falling back to public address %s", 
		ipStr, peer.PublicAddr)
	
	// Fallback: Try public address
	publicAddr, err := net.ResolveUDPAddr("udp4", peer.PublicAddr)
	if err != nil {
		log.Printf("P2P: Failed to resolve public address %s: %v", peer.PublicAddr, err)
		return
	}
	
	// Update connection to use public address
	m.mu.Lock()
	conn.RemoteAddr = publicAddr
	conn.IsLocalNetwork = false
	m.mu.Unlock()
	
	// Perform handshake to public address
	m.performHandshake(conn, false)
}

// tryHandshakeWithTimeout attempts handshake with a specific timeout
// Returns true if peer responds (connection established)
func (m *Manager) tryHandshakeWithTimeout(conn *Connection, timeout time.Duration) bool {
	handshakeMsg := []byte("P2P_HANDSHAKE")
	deadline := time.Now().Add(timeout)
	
	// Send handshake packets until timeout or success
	for time.Now().Before(deadline) {
		_, err := m.listener.WriteToUDP(handshakeMsg, conn.RemoteAddr)
		if err != nil {
			log.Printf("Handshake send error to %s: %v", conn.PeerIP, err)
		}
		
		// Check if peer responded (connection marked as connected)
		m.mu.RLock()
		connected := m.isPeerConnected(conn.PeerIP.String())
		m.mu.RUnlock()
		
		if connected {
			return true
		}
		
		time.Sleep(HandshakeInterval)
	}
	
	return false
}

// performHandshake performs NAT hole punching handshake
func (m *Manager) performHandshake(conn *Connection, isLocal bool) {
	// Send multiple handshake packets to establish NAT mapping
	handshakeMsg := []byte("P2P_HANDSHAKE")
	
	for i := 0; i < HandshakeAttempts; i++ {
		_, err := m.listener.WriteToUDP(handshakeMsg, conn.RemoteAddr)
		if err != nil {
			log.Printf("Handshake send error to %s: %v", conn.PeerIP, err)
		}
		time.Sleep(HandshakeInterval)
	}
}

// SendPacket sends a packet to a peer via P2P
func (m *Manager) SendPacket(peerIP net.IP, data []byte) error {
	m.mu.RLock()
	conn, exists := m.connections[peerIP.String()]
	m.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("no P2P connection to %s", peerIP)
	}
	
	// Send via UDP listener
	_, err := m.listener.WriteToUDP(data, conn.RemoteAddr)
	return err
}

// receivePackets receives packets from UDP socket
func (m *Manager) receivePackets() {
	defer m.wg.Done()
	
	buf := make([]byte, 2048)
	
	for {
		select {
		case <-m.stopCh:
			return
		default:
		}
		
		m.listener.SetReadDeadline(time.Now().Add(ReadTimeout))
		n, remoteAddr, err := m.listener.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-m.stopCh:
				return
			default:
				log.Printf("P2P receive error: %v", err)
			}
			continue
		}
		
		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			
			// Handle handshake messages
			if string(data) == "P2P_HANDSHAKE" {
				m.handleHandshake(remoteAddr)
				continue
			}
			
			// Find which peer this packet is from
			peerIP := m.findPeerByAddr(remoteAddr)
			if peerIP != nil {
				// Update peer's last seen time
				m.updatePeerLastSeen(peerIP)
				
				// Call packet handler
				m.mu.RLock()
				handler := m.onPacket
				m.mu.RUnlock()
				
				if handler != nil {
					handler(peerIP, data)
				}
			}
		}
	}
}

// handleHandshake handles incoming handshake packets
func (m *Manager) handleHandshake(remoteAddr *net.UDPAddr) {
	// Find if this is from a known peer
	peerIP := m.findPeerByAddr(remoteAddr)
	if peerIP != nil {
		m.mu.Lock()
		ipStr := peerIP.String()
		
		// Check if this is a local address connection
		isLocalConnection := false
		if peer, exists := m.peers[ipStr]; exists {
			// Compare the address that responded with peer's local address
			if peer.LocalAddr == remoteAddr.String() {
				isLocalConnection = true
			}
		}
		
		// Update connection's remote address to the one that actually worked
		if conn, exists := m.connections[ipStr]; exists {
			// Update to the address that successfully sent us a packet
			conn.RemoteAddr = remoteAddr
			conn.IsLocalNetwork = isLocalConnection
		}
		// Mark peer as connected and track connection type
		if peer, exists := m.peers[ipStr]; exists {
			// Only log on transition from not-connected -> connected to avoid log spam
			peer.mu.RLock()
			alreadyConnected := peer.Connected
			peer.mu.RUnlock()
			// Update connection flags regardless
			peer.SetLocalConnection(isLocalConnection)
			if !alreadyConnected {
				peer.SetConnected(true)
				if isLocalConnection {
					log.Printf("P2P LOCAL connection established with %s via %s", peerIP, remoteAddr)
				} else {
					log.Printf("P2P PUBLIC connection established with %s via %s", peerIP, remoteAddr)
				}
			}
		}
		m.mu.Unlock()
		
		// Send handshake response
		m.listener.WriteToUDP([]byte("P2P_HANDSHAKE"), remoteAddr)
	}
}

// findPeerByAddr finds a peer by their remote address
func (m *Manager) findPeerByAddr(addr *net.UDPAddr) net.IP {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	addrStr := addr.String()
	
	// Check both public and local addresses
	for _, peer := range m.peers {
		if peer.PublicAddr == addrStr || peer.LocalAddr == addrStr {
			return peer.TunnelIP
		}
	}
	
	// Also check connections
	for _, conn := range m.connections {
		// Skip nil connections
		if conn == nil || conn.RemoteAddr == nil {
			continue
		}
		// Exact match on remote address (IP:port)
		if conn.RemoteAddr.String() == addrStr {
			return conn.PeerIP
		}
	}
	
	return nil
}

// updatePeerLastSeen updates the last seen time for a peer
func (m *Manager) updatePeerLastSeen(peerIP net.IP) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if peer, exists := m.peers[peerIP.String()]; exists {
		peer.mu.Lock()
		peer.LastSeen = time.Now()
		peer.mu.Unlock()
	}
}

// GetLocalPort returns the local UDP port
func (m *Manager) GetLocalPort() int {
	return m.localPort
}

// isPeerConnected checks if a peer is actually connected (handshake complete)
// Must be called with m.mu held (read or write lock)
func (m *Manager) isPeerConnected(ipStr string) bool {
	if peer, exists := m.peers[ipStr]; exists {
		peer.mu.RLock()
		connected := peer.Connected
		peer.mu.RUnlock()
		return connected
	}
	return false
}

// IsConnected checks if we have a P2P connection to a peer
func (m *Manager) IsConnected(peerIP net.IP) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	ipStr := peerIP.String()
	
	// Check if connection exists
	if _, exists := m.connections[ipStr]; !exists {
		return false
	}
	
	// Check if peer is marked as connected (handshake complete)
	return m.isPeerConnected(ipStr)
}

// RemovePeer removes a peer from the P2P manager
func (m *Manager) RemovePeer(peerIP net.IP) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	ipStr := peerIP.String()
	
	// Close connection if exists
	if conn, exists := m.connections[ipStr]; exists {
		// Stop connection goroutines
		select {
		case <-conn.stopCh:
			// Already closed
		default:
			close(conn.stopCh)
		}
		delete(m.connections, ipStr)
		log.Printf("P2P connection to %s removed", ipStr)
	}
	
	// Remove peer info
	if _, exists := m.peers[ipStr]; exists {
		delete(m.peers, ipStr)
		log.Printf("P2P peer %s removed", ipStr)
	}
}

// DetectNATType detects the local NAT type
func (m *Manager) DetectNATType(serverAddr string) {
	log.Println("Detecting NAT type...")
	
	var detectedType nat.NATType
	
	// Try detection with server address if available
	if serverAddr != "" {
		natType, err := m.natDetector.DetectNATType(serverAddr)
		if err != nil {
			log.Printf("NAT detection with server failed: %v, using simple detection", err)
			detectedType = m.natDetector.DetectNATTypeSimple()
		} else {
			detectedType = natType
		}
	} else {
		detectedType = m.natDetector.DetectNATTypeSimple()
	}
	
	m.natTypeMux.Lock()
	m.myNATType = detectedType
	m.natTypeMux.Unlock()
	
	log.Printf("NAT Type detected: %s (Level: %d)", detectedType, detectedType.GetLevel())
}

// GetNATType returns the detected NAT type
func (m *Manager) GetNATType() nat.NATType {
	m.natTypeMux.RLock()
	defer m.natTypeMux.RUnlock()
	return m.myNATType
}

// SetNATType sets the NAT type (useful when server provides this info)
func (m *Manager) SetNATType(natType nat.NATType) {
	m.natTypeMux.Lock()
	defer m.natTypeMux.Unlock()
	m.myNATType = natType
	log.Printf("NAT Type set to: %s (Level: %d)", natType, natType.GetLevel())
}

// ShouldInitiateConnectionToPeer determines if we should initiate connection to peer
// based on NAT types (lower-level NAT connects to higher-level NAT)
func (m *Manager) ShouldInitiateConnectionToPeer(peerIP net.IP) bool {
	m.mu.RLock()
	peer, exists := m.peers[peerIP.String()]
	m.mu.RUnlock()
	
	if !exists {
		// Default to true if peer not found
		return true
	}
	
	myNATType := m.GetNATType()
	peerNATType := peer.GetNATType()
	
	// If either NAT type is unknown, default to initiating
	if myNATType == nat.NATUnknown || peerNATType == nat.NATUnknown {
		return true
	}
	
	// Lower-level (better) NAT should initiate
	shouldInitiate := myNATType.ShouldInitiateConnection(peerNATType)
	
	log.Printf("P2P connection decision for %s: My NAT=%s (level %d), Peer NAT=%s (level %d), Should initiate=%v",
		peerIP, myNATType, myNATType.GetLevel(), peerNATType, peerNATType.GetLevel(), shouldInitiate)
	
	return shouldInitiate
}

// CanEstablishP2PWith checks if P2P connection is likely to succeed with peer
func (m *Manager) CanEstablishP2PWith(peerIP net.IP) bool {
	m.mu.RLock()
	peer, exists := m.peers[peerIP.String()]
	m.mu.RUnlock()
	
	if !exists {
		// Assume possible if peer not found
		return true
	}
	
	myNATType := m.GetNATType()
	peerNATType := peer.GetNATType()
	
	// If either NAT type is unknown, attempt P2P
	if myNATType == nat.NATUnknown || peerNATType == nat.NATUnknown {
		return true
	}
	
	canTraverse := myNATType.CanTraverseWith(peerNATType)
	
	if !canTraverse {
		log.Printf("P2P traversal unlikely between %s (NAT: %s) and peer %s (NAT: %s) - will use server relay",
			myNATType, myNATType, peerIP, peerNATType)
	}
	
	return canTraverse
}
