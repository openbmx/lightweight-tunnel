package p2p

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"
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
	LocalAddr      *net.UDPAddr
	RemoteAddr     *net.UDPAddr
	Conn           *net.UDPConn
	PeerIP         net.IP // Tunnel IP of the peer
	IsLocalNetwork bool   // Whether this connection is via local network
	sendQueue      chan []byte
	stopCh         chan struct{}
	wg             sync.WaitGroup
}

// Manager manages P2P connections
type Manager struct {
	localPort        int
	connections      map[string]*Connection // Key: peer tunnel IP string
	listener         *net.UDPConn
	peers            map[string]*PeerInfo // Peer information
	mu               sync.RWMutex
	stopCh           chan struct{}
	localNAT         NATType
	wg               sync.WaitGroup
	onPacket         func(peerIP net.IP, data []byte) // Callback for received packets
	handshakeTimeout time.Duration
}

// NewManager creates a new P2P connection manager
func NewManager(port int) *Manager {
	return &Manager{
		localPort:        port,
		connections:      make(map[string]*Connection),
		peers:            make(map[string]*PeerInfo),
		stopCh:           make(chan struct{}),
		localNAT:         NATUnknown,
		handshakeTimeout: 5 * time.Second,
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

	m.wg.Wait()
}

// SetPacketHandler sets the callback for received packets
func (m *Manager) SetPacketHandler(handler func(peerIP net.IP, data []byte)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onPacket = handler
}

// SetHandshakeTimeout sets the maximum time to wait for a P2P connection before falling back to server routing.
func (m *Manager) SetHandshakeTimeout(timeout time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if timeout > 0 {
		m.handshakeTimeout = timeout
	} else {
		m.handshakeTimeout = LocalConnectionTimeout
	}
}

// SetLocalNATType sets the detected NAT type for local side to guide initiation priority.
func (m *Manager) SetLocalNATType(n NATType) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.localNAT = n
}

// AddPeer adds peer information for P2P connection
func (m *Manager) AddPeer(peer *PeerInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()

	ipStr := peer.TunnelIP.String()
	m.peers[ipStr] = peer

	log.Printf("Added P2P peer: %s (public: %s, local: %s)", ipStr, peer.PublicAddr, peer.LocalAddr)
}

func (m *Manager) getHandshakeTimeout() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.handshakeTimeout
}

// ConnectToPeer establishes a P2P connection to a peer
// Priority order: 1) Local network address, 2) Public address, 3) Server fallback
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

	// If both peers are symmetric NAT, immediately fall back to server relay.
	if peer.NATType == NATSymmetric && m.localNAT == NATSymmetric {
		peer.SetThroughServer(true)
		log.Printf("P2P fallback to server for %s: both sides symmetric NAT", ipStr)
		return nil
	}

	// Decide who should initiate: less restrictive NAT should start first.
	shouldInitiate := true
	if peer.NATType != NATUnknown && m.localNAT != NATUnknown &&
		m.localNAT.priority() > peer.NATType.priority() {
		shouldInitiate = false
	}
	delay := time.Duration(0)
	if !shouldInitiate {
		delay = HandshakeInterval * 3
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

			// Start local handshake first with optional delay
			go func(d time.Duration) {
				if d > 0 {
					time.Sleep(d)
				}
				m.performHandshakeWithFallback(conn, peer)
			}(delay)
			go m.monitorConnectionTimeout(ipStr)
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
	go func(d time.Duration) {
		if d > 0 {
			time.Sleep(d)
		}
		m.performHandshake(conn, false)
	}(delay)
	go m.monitorConnectionTimeout(ipStr)

	return nil
}

// performHandshakeWithFallback tries local address first, then falls back to public address
func (m *Manager) performHandshakeWithFallback(conn *Connection, peer *PeerInfo) {
	ipStr := conn.PeerIP.String()

	// First: Try local address with timeout
	log.Printf("P2P: Trying local address %s for peer %s", conn.RemoteAddr, ipStr)

	localSuccess := m.tryHandshakeWithTimeout(conn, m.getHandshakeTimeout())

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

func (m *Manager) monitorConnectionTimeout(ipStr string) {
	timeout := m.getHandshakeTimeout()
	if timeout <= 0 {
		return
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-timer.C:
	case <-m.stopCh:
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.isPeerConnected(ipStr) {
		return
	}

	if peer, exists := m.peers[ipStr]; exists {
		peer.SetThroughServer(true)
		log.Printf("P2P connection to %s timed out after %s, falling back to server routing", ipStr, timeout)
	}
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
		// Mark peer as connected and track connection type. If the responding
		// port differs from the advertised one, treat the peer as symmetric
		// and update the reachable public address to the observed endpoint.
		if peer, exists := m.peers[ipStr]; exists {
			if !isLocalConnection {
				peer.mu.Lock()
				if peer.PublicAddr != "" && peer.PublicAddr != remoteAddr.String() {
					peer.PublicAddr = remoteAddr.String()
					peer.NATType = NATSymmetric
				}
				peer.mu.Unlock()
			}
			peer.SetConnected(true)
			peer.SetLocalConnection(isLocalConnection)
			if isLocalConnection {
				log.Printf("P2P LOCAL connection established with %s via %s", peerIP, remoteAddr)
			} else {
				log.Printf("P2P PUBLIC connection established with %s via %s", peerIP, remoteAddr)
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
	addrIP := addr.IP.String()

	// Check both public and local addresses
	for _, peer := range m.peers {
		if peer.PublicAddr == addrStr || peer.LocalAddr == addrStr {
			return peer.TunnelIP
		}
		if hostMatches(peer.PublicAddr, addrIP) || hostMatches(peer.LocalAddr, addrIP) {
			return peer.TunnelIP
		}
	}

	// Also check connections
	for ipStr, conn := range m.connections {
		if conn.RemoteAddr.String() == addrStr {
			return conn.PeerIP
		}
		// Parse IP from string
		if ip := net.ParseIP(ipStr); ip != nil {
			return ip
		}
	}

	return nil
}

func hostMatches(addr, ip string) bool {
	if addr == "" || ip == "" {
		return false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return host == ip
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
