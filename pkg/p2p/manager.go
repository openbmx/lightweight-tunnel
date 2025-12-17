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
)

// Connection represents a P2P UDP connection to a peer
type Connection struct {
	LocalAddr  *net.UDPAddr
	RemoteAddr *net.UDPAddr
	Conn       *net.UDPConn
	PeerIP     net.IP // Tunnel IP of the peer
	sendQueue  chan []byte
	stopCh     chan struct{}
	wg         sync.WaitGroup
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
}

// NewManager creates a new P2P connection manager
func NewManager(port int) *Manager {
	return &Manager{
		localPort:   port,
		connections: make(map[string]*Connection),
		peers:       make(map[string]*PeerInfo),
		stopCh:      make(chan struct{}),
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

// AddPeer adds peer information for P2P connection
func (m *Manager) AddPeer(peer *PeerInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	ipStr := peer.TunnelIP.String()
	m.peers[ipStr] = peer
	
	log.Printf("Added P2P peer: %s (public: %s, local: %s)", ipStr, peer.PublicAddr, peer.LocalAddr)
}

// ConnectToPeer establishes a P2P connection to a peer
func (m *Manager) ConnectToPeer(peerTunnelIP net.IP) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	ipStr := peerTunnelIP.String()
	
	// Check if already connected
	if _, exists := m.connections[ipStr]; exists {
		return nil
	}
	
	peer, exists := m.peers[ipStr]
	if !exists {
		return fmt.Errorf("peer %s not found", ipStr)
	}
	
	// Try to parse peer's public address
	remoteAddr, err := net.ResolveUDPAddr("udp4", peer.PublicAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve peer address: %v", err)
	}
	
	// Create connection
	conn := &Connection{
		RemoteAddr: remoteAddr,
		PeerIP:     peerTunnelIP,
		sendQueue:  make(chan []byte, 100),
		stopCh:     make(chan struct{}),
	}
	
	m.connections[ipStr] = conn
	
	// Send initial handshake packet for NAT traversal
	go m.performHandshake(conn)
	
	log.Printf("Attempting P2P connection to %s at %s", ipStr, peer.PublicAddr)
	
	return nil
}

// performHandshake performs NAT hole punching handshake
func (m *Manager) performHandshake(conn *Connection) {
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
		// Mark peer as connected
		m.mu.Lock()
		if peer, exists := m.peers[peerIP.String()]; exists {
			peer.SetConnected(true)
			log.Printf("P2P connection established with %s", peerIP)
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
	for _, peer := range m.peers {
		if peer.PublicAddr == addrStr {
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

// IsConnected checks if we have a P2P connection to a peer
func (m *Manager) IsConnected(peerIP net.IP) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	_, exists := m.connections[peerIP.String()]
	return exists
}
