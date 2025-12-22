package tunnel

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"

	"github.com/openbmx/lightweight-tunnel/internal/config"
	"github.com/openbmx/lightweight-tunnel/pkg/crypto"
	"github.com/openbmx/lightweight-tunnel/pkg/faketcp"
	"github.com/openbmx/lightweight-tunnel/pkg/fec"
	"github.com/openbmx/lightweight-tunnel/pkg/nat"
	"github.com/openbmx/lightweight-tunnel/pkg/p2p"
	"github.com/openbmx/lightweight-tunnel/pkg/routing"
	"github.com/openbmx/lightweight-tunnel/pkg/xdp"
)

const (
	PacketTypeData         = 0x01
	PacketTypeKeepalive    = 0x02
	PacketTypePeerInfo     = 0x03 // Peer discovery/advertisement
	PacketTypeRouteInfo    = 0x04 // Route information exchange
	PacketTypePublicAddr   = 0x05 // Server tells client its public address
	PacketTypePunch        = 0x06 // Server requests simultaneous hole-punch
	PacketTypeConfigUpdate = 0x07 // Server pushes new config (e.g., rotated key)
	PacketTypeP2PRequest   = 0x08 // Client requests P2P connection to another client
	PacketTypeIPRegister   = 0x09 // Client requests IP registration (centralized management)
	PacketTypeIPAccept     = 0x0A // Server accepts IP registration
	PacketTypeIPReject     = 0x0B // Server rejects IP registration (conflict)
	PacketTypeDataPlain    = 0x0C // Plaintext data (for encrypted-only passthrough, like HTTPS/SSH)
	PacketTypeFEC          = 0x0D // FEC shard packet

	// IPv4 constants
	IPv4Version      = 4
	IPv4SrcIPOffset  = 12
	IPv4DstIPOffset  = 16
	IPv4MinHeaderLen = 20

	// P2P timing constants
	P2PRegistrationDelay           = 100 * time.Millisecond // Delay to ensure peer registration completes
	P2PHandshakeWaitTime           = 2 * time.Second        // Time to wait for P2P handshake to complete before updating routes
	P2PReconnectPublicAddrWaitTime = 2 * time.Second        // Time to wait for public address after reconnection
	P2PMaxRetries                  = 5
	P2PMaxBackoffSeconds           = 32 // Maximum backoff delay in seconds

	// Queue management constants
	QueueSendTimeout = 100 * time.Millisecond // Timeout for queue send operations to handle temporary congestion

	// Connection health constants
	// IdleConnectionTimeout is the maximum time without receiving packets before considering connection dead
	// Set to 3x the keepalive interval to allow for some packet loss
	IdleConnectionTimeout = 30 * time.Second // 3x default keepalive (10s)

	// Rotation and advertisement timing
	KeyRotationGracePeriod     = 15 * time.Second
	DefaultRouteAdvertInterval = 60 * time.Second

	packetBufferSlack = 128 // Extra bytes to leave headroom for prepending headers without reallocations
)

// enqueueWithTimeout attempts to enqueue a packet, waiting briefly for capacity.
// Returns true when the packet was queued, or false when stopCh is closed or the timeout elapses.
func enqueueWithTimeout(queue chan []byte, packet []byte, stopCh <-chan struct{}) bool {
	select {
	case queue <- packet:
		return true
	default:
	}

	timer := time.NewTimer(QueueSendTimeout)
	defer timer.Stop()

	select {
	case queue <- packet:
		return true
	case <-stopCh:
		return false
	case <-timer.C:
		return false
	}
}

// ClientConnection represents a single client connection
type ClientConnection struct {
	conn         faketcp.ConnAdapter // Changed to interface for both UDP and Raw socket modes
	sendQueue    chan []byte
	recvQueue    chan []byte
	clientIP     net.IP
	stopCh       chan struct{}
	stopOnce     sync.Once
	wg           sync.WaitGroup
	lastPeerInfo string // Last peer info string sent by this client
	cipher       *crypto.Cipher
	cipherGen    uint64
	lastRecvTime time.Time // Last time we received a packet from this client
	mu           sync.RWMutex
	fecManager   *FECManager
	nextPacketID uint32
}

// ConfigUpdateMessage carries server-pushed configuration updates.
type ConfigUpdateMessage struct {
	Key    string   `json:"key"`
	Routes []string `json:"routes,omitempty"`
}

type clientRoute struct {
	network *net.IPNet
	client  *ClientConnection
}

// clientInfo is a helper type for broadcasting peer info
type clientInfo struct {
	client       *ClientConnection
	clientIP     net.IP
	lastPeerInfo string
}

func (c *ClientConnection) setCipherWithGen(cipher *crypto.Cipher, gen uint64) {
	c.mu.Lock()
	c.cipher = cipher
	c.cipherGen = gen
	c.mu.Unlock()
}

func (c *ClientConnection) getCipher() (*crypto.Cipher, uint64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cipher, c.cipherGen
}

// Tunnel represents a lightweight tunnel
type Tunnel struct {
	config         *config.Config
	configFilePath string
	fec            *fec.FEC
	cipher         *crypto.Cipher // Encryption cipher (nil if no key)
	cipherGen      uint64
	prevCipher     *crypto.Cipher
	prevCipherGen  uint64
	prevCipherExp  time.Time
	cipherMux      sync.RWMutex
	configMux      sync.RWMutex
	conn           faketcp.ConnAdapter          // Used in client mode (interface for both modes)
	listener       faketcp.ListenerAdapter      // Used in server mode (interface for both modes)
	clients        map[string]*ClientConnection // Used in server mode (key: IP address)
	clientsMux     sync.RWMutex
	allClients     map[*ClientConnection]struct{} // Tracks all active clients (including those without registered tunnel IP)
	allClientsMux  sync.RWMutex
	tunName        string
	tunFile        *TunDevice
	stopCh         chan struct{}
	stopOnce       sync.Once // Ensures Stop() is only executed once
	wg             sync.WaitGroup
	sendQueue      chan []byte // Used in client mode
	recvQueue      chan []byte // Used in client mode

	packetPool    *sync.Pool
	packetBufSize int

	xdpAccel *xdp.Accelerator

	fecManager   *FECManager
	nextPacketID uint32

	// P2P and routing
	p2pManager      *p2p.Manager          // P2P connection manager
	routingTable    *routing.RoutingTable // Routing table
	myTunnelIP      net.IP                // My tunnel IP address
	serverTunnelIP  net.IP                // Server's tunnel IP address (client mode only)
	publicAddr      string                // Public address as seen by server (for NAT traversal)
	publicAddrMux   sync.RWMutex          // Protects publicAddr
	connMux         sync.Mutex            // Protects t.conn during reconnects

	// Connection health tracking (client mode)
	lastRecvTime time.Time  // Last time we received ANY packet from server
	lastRecvMux  sync.Mutex // Protects lastRecvTime

	routeMux         sync.RWMutex
	advertisedRoutes []clientRoute
	clientRoutes     map[*ClientConnection][]string

	// On-demand P2P state tracking
	pendingP2PRequests map[string]time.Time // Tracks pending P2P requests (key: target client IP)
	p2pRequestMux      sync.Mutex           // Protects pendingP2PRequests
}

// prependPacketType adds a leading packet type byte to the payload.
// It prefers in-place expansion when spare capacity exists (which happens when
// the buffer was obtained from packetPool with slack). When reusing the buffer
// in-place, it uses an optimized approach that minimizes data movement.
// Returns the new slice and a boolean indicating whether the original backing buffer was reused.
func prependPacketType(packet []byte, packetType byte) ([]byte, bool) {
	origLen := len(packet)
	// Check if we have capacity to expand in-place
	if cap(packet) >= origLen+1 {
		// Expand the slice by 1 byte at the beginning
		// We need to shift data, but we can do it more efficiently
		// by growing at the end first, then moving
		packet = packet[:origLen+1]
		// Shift data right by 1 byte
		// Using copy with overlapping regions is safe and optimized by the runtime
		copy(packet[1:], packet[:origLen])
		packet[0] = packetType
		return packet, true
	}

	// No capacity available - allocate new buffer with slack for future prepends
	// This should rarely happen if buffers are allocated with proper slack
	newPacket := make([]byte, origLen+1, origLen+1+packetBufferSlack)
	newPacket[0] = packetType
	copy(newPacket[1:], packet)
	return newPacket, false
}

// getPacketBuffer pulls a reusable packet buffer sized for tunnel traffic.
func (t *Tunnel) getPacketBuffer() []byte {
	if t.packetPool == nil || t.packetBufSize == 0 {
		return make([]byte, t.config.MTU+packetBufferSlack)
	}
	return t.packetPool.Get().([]byte)
}

// releasePacketBuffer returns a buffer to the pool when it matches the
// expected capacity, keeping pooled slices uniform.
func (t *Tunnel) releasePacketBuffer(buf []byte) {
	if t.packetPool == nil || t.packetBufSize == 0 {
		return
	}
	if cap(buf) >= t.packetBufSize {
		t.packetPool.Put(buf[:t.packetBufSize])
	}
}

// NewTunnel creates a new tunnel instance
func NewTunnel(cfg *config.Config, configFilePath string) (*Tunnel, error) {
	// Force rawtcp mode - this is the only supported transport now
	cfg.Transport = "rawtcp"
	faketcp.SetMode(faketcp.ModeRaw)

	// Check if raw socket is supported (requires root)
	if err := faketcp.CheckRawSocketSupport(); err != nil {
		return nil, fmt.Errorf("Raw Socket模式需要root权限运行\n"+
			"请使用以下命令运行: sudo ./lightweight-tunnel -m %s ...\n"+
			"错误详情: %v", cfg.Mode, err)
	}

	// Apply kernel-level optimizations (best effort)
	applyKernelTunings(cfg.EnableKernelTune)

	log.Printf("✅ 使用 Raw Socket 模式 (真正的TCP伪装，类似udp2raw)")
	log.Printf("✅ 性能优化：低延迟，高吞吐量")

	// Auto-detect MTU if not specified or set to 0
	if cfg.MTU == 0 {
		log.Println("🔍 MTU未指定，启动自动检测...")

		// Detect network type
		networkType := AutoDetectNetworkType()
		log.Printf("   检测到网络类型: %s", networkType)

		// Get recommended MTU for network type
		recommendedMTU := GetRecommendedMTU(networkType)
		cfg.MTU = recommendedMTU

		log.Printf("✅ 自动设置MTU为: %d", cfg.MTU)

		// If in client mode and remote address is available, do path MTU discovery
		if cfg.Mode == "client" && cfg.RemoteAddr != "" {
			discovery := NewMTUDiscovery(cfg.RemoteAddr, cfg.MTU)
			if optimalMTU, err := discovery.DiscoverOptimalMTU(); err == nil {
				cfg.MTU = optimalMTU
				log.Printf("✅ 通过路径MTU探测优化为: %d", cfg.MTU)
			} else {
				log.Printf("⚠️  路径MTU探测失败: %v，使用推荐值 %d", err, cfg.MTU)
			}
		}
	} else {
		log.Printf("使用配置的MTU: %d", cfg.MTU)
	}

	// Create FEC encoder/decoder
	// Calculate optimal shard size to avoid excessive header overhead
	// Protocol overhead breakdown:
	//   - IP header: 20 bytes (IPv4 standard)
	//   - TCP header: 20 bytes (without options)
	//   - Encryption overhead: ~50 bytes (nonce + auth tag + padding)
	//   Total: ~90 bytes per packet
	const protocolOverhead = 90
	// Minimum shard size to avoid creating too many small fragments
	// Small fragments (< 512 bytes) cause high PPS and trigger ISP QoS
	const minShardSize = 512
	
	// Calculate shard size: use full MTU minus overhead for each shard
	shardSize := cfg.MTU - protocolOverhead
	if shardSize < minShardSize {
		log.Printf("Warning: MTU (%d) too small for optimal FEC performance. Minimum recommended: %d", cfg.MTU, minShardSize+protocolOverhead)
		shardSize = minShardSize
	}
	
	// Log FEC configuration for debugging
	bandwidthOverhead := float64(cfg.FECParityShards) / float64(cfg.FECDataShards) * 100
	log.Printf("FEC configuration: %d data shards + %d parity shards (%.1f%% bandwidth overhead)", 
		cfg.FECDataShards, cfg.FECParityShards, bandwidthOverhead)
	log.Printf("FEC shard size: %d bytes (avoids small packet fragmentation)", shardSize)
	
	fecCodec, err := fec.NewFEC(cfg.FECDataShards, cfg.FECParityShards, shardSize)
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

		// Adjust MTU to prevent TCP segmentation of encrypted packets in raw TCP mode
		// In raw TCP mode, WritePacket segments data into 1400-byte chunks.
		// To avoid segmenting encrypted packets (which breaks decryption), we must ensure:
		// encrypted_size = plaintext_size + overhead <= 1400
		// plaintext_size = tunnel_packet_payload + 1 (packet type byte)
		// Therefore: MTU + 1 + overhead <= 1400
		// MTU <= 1400 - 1 - overhead
		if cfg.Transport == "rawtcp" {
			const maxRawTCPSegment = 1400
			const packetTypeOverhead = 1
			encryptionOverhead := cipher.Overhead()
			maxSafeMTU := maxRawTCPSegment - packetTypeOverhead - encryptionOverhead

			if cfg.MTU > maxSafeMTU {
				log.Printf("⚠️  Adjusting MTU from %d to %d to prevent TCP segmentation of encrypted packets", cfg.MTU, maxSafeMTU)
				cfg.MTU = maxSafeMTU
			}
		}
	}

	packetBufSize := cfg.MTU + packetBufferSlack
	if packetBufSize < packetBufferSlack {
		packetBufSize = packetBufferSlack
	}

	var accel *xdp.Accelerator
	if cfg.EnableXDP {
		accel = xdp.NewAccelerator(true)
		log.Println("✅ eBPF/XDP fast path enabled for encrypted-flow classification")
	} else {
		log.Println("XDP fast path disabled, using regular path")
	}

	t := &Tunnel{
		config:             cfg,
		configFilePath:     configFilePath,
		fec:                fecCodec,
		cipher:             cipher,
		stopCh:             make(chan struct{}),
		myTunnelIP:         myIP,
		packetBufSize:      packetBufSize,
		clientRoutes:       make(map[*ClientConnection][]string),
		allClients:         make(map[*ClientConnection]struct{}),
		xdpAccel:           accel,
		pendingP2PRequests: make(map[string]time.Time),
	}

	if fecCodec != nil {
		t.fecManager = NewFECManager(fecCodec)
	}

	t.packetPool = &sync.Pool{
		New: func() any {
			return make([]byte, packetBufSize)
		},
	}

	if cipher != nil {
		t.cipherGen = 1
	}

	// Initialize P2P manager if enabled
	if cfg.P2PEnabled && cfg.Mode == "client" {
		t.p2pManager = p2p.NewManager(cfg.P2PPort)
		// Set configurable keepalive interval (defaults to 25 seconds for reduced network traffic)
		keepaliveInterval := time.Duration(cfg.P2PKeepAliveInterval) * time.Second
		t.p2pManager.SetKeepaliveInterval(keepaliveInterval)
		t.routingTable = routing.NewRoutingTable(cfg.MaxHops)
	}

	if cfg.Mode == "client" {
		t.sendQueue = make(chan []byte, cfg.SendQueueSize)
		t.recvQueue = make(chan []byte, cfg.RecvQueueSize)
		
		// Determine server's tunnel IP for P2P exclusion
		serverTunnelAddr, err := GetPeerIP(cfg.TunnelAddr)
		if err == nil {
			parts := strings.Split(serverTunnelAddr, "/")
			if len(parts) > 0 {
				serverIP := net.ParseIP(parts[0])
				if serverIP != nil {
					t.serverTunnelIP = serverIP
					log.Printf("Server tunnel IP: %s (will not use P2P for this address)", serverIP)
				}
			}
		}
		
		// Register server as a peer in the routing table so stats show the
		// server route even when no other clients are present.
		if t.routingTable != nil {
			t.registerServerPeer()
		}
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
	tunDev, err := t.createTUNWithFallback()
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

		// Periodically announce routes to server
		if len(t.getAdvertisedRoutes()) > 0 {
			t.wg.Add(1)
			go t.routeAdvertLoop()
		}
	} else {
		// Server mode: start accepting clients
		if err := t.startServer(); err != nil {
			t.tunFile.Close()
			return fmt.Errorf("failed to start as server: %v", err)
		}

		// Enable periodic config/key push if configured
		if t.config.ConfigPushInterval > 0 && t.cipher != nil {
			t.wg.Add(1)
			go t.configPushLoop()
		}
	}

	log.Printf("Tunnel started in %s mode", t.config.Mode)
	return nil
}

// Stop stops the tunnel
func (t *Tunnel) Stop() {
	// Use sync.Once to ensure Stop() logic only runs once
	t.stopOnce.Do(func() {
		// Signal all tunnel goroutines to stop as early as possible
		close(t.stopCh)

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

		// Also close any clients that haven't been registered with a tunnel IP yet
		t.allClientsMux.RLock()
		for client := range t.allClients {
			client.stopOnce.Do(func() {
				if err := client.conn.Close(); err != nil {
					log.Printf("Error closing client connection: %v", err)
				}
				close(client.stopCh)
			})
		}
		t.allClientsMux.RUnlock()

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

func (t *Tunnel) trackClientConnection(client *ClientConnection) {
	t.allClientsMux.Lock()
	t.allClients[client] = struct{}{}
	t.allClientsMux.Unlock()
}

func (t *Tunnel) untrackClientConnection(client *ClientConnection) {
	t.allClientsMux.Lock()
	delete(t.allClients, client)
	t.allClientsMux.Unlock()
}

// addClient adds a client to the routing table
func (t *Tunnel) addClient(client *ClientConnection, ip net.IP) {
	t.clientsMux.Lock()
	defer t.clientsMux.Unlock()

	client.mu.Lock()
	if client.clientIP != nil {
		client.mu.Unlock()
		return
	}
	client.clientIP = ip
	client.mu.Unlock()

	ipStr := ip.String()
	if existing, ok := t.clients[ipStr]; ok {
		if existing == client {
			return
		}
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
		// Only remove if this client still owns the IP
		// Prevents race where a new client with the same IP has already replaced this one
		if currentClient, exists := t.clients[ipStr]; exists && currentClient == client {
			delete(t.clients, ipStr)
			log.Printf("Client unregistered: %s (remaining clients: %d)", ipStr, len(t.clients))
		} else if exists {
			log.Printf("Client %s no longer owns IP %s, skipping removal (already replaced)", client.conn.RemoteAddr(), ipStr)
		}
	}
	t.clientsMux.Unlock()

	if clientIP != nil {
		// Remove from routing table if mesh routing enabled (outside of lock)
		if t.routingTable != nil {
			t.routingTable.RemovePeer(clientIP)
			log.Printf("Removed peer %s from routing table", clientIP)
		}

		// Clean advertised routes
		t.cleanupClientRoutes(client)

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

	// Snapshot clients to avoid holding lock during network IO
	t.clientsMux.RLock()
	clients := make([]*ClientConnection, 0, len(t.clients))
	for _, client := range t.clients {
		if client.clientIP != nil && !client.clientIP.Equal(disconnectedIP) {
			clients = append(clients, client)
		}
	}
	t.clientsMux.RUnlock()

	// Perform network I/O without holding the lock
	for _, client := range clients {
		encryptedPacket, err := t.encryptForClient(client, fullPacket)
		if err != nil {
			log.Printf("Failed to encrypt disconnect notification: %v", err)
			continue
		}
		if err := client.conn.WritePacket(encryptedPacket); err != nil {
			log.Printf("Failed to send disconnect notification to %s: %v", client.clientIP, err)
		}
	}
}

// getClientByIP retrieves a client by IP address
func (t *Tunnel) getClientByIP(ip net.IP) *ClientConnection {
	t.clientsMux.RLock()
	defer t.clientsMux.RUnlock()
	return t.clients[ip.String()]
}

func isSafeTunName(name string) bool {
	if name == "" {
		return true
	}
	if len(name) > 32 {
		return false
	}
	for _, r := range name {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// createTUNWithFallback tries to create the requested TUN name, falling back to auto assignment on conflict.
func (t *Tunnel) createTUNWithFallback() (*TunDevice, error) {
	if t.config.TunName == "" {
		return CreateTUN("")
	}

	if !isSafeTunName(t.config.TunName) {
		log.Printf("Unsafe tun name %s, falling back to auto-generated name", t.config.TunName)
		return CreateTUN("")
	}

	dev, err := CreateTUN(t.config.TunName)
	if err == nil {
		return dev, nil
	}

	log.Printf("Failed to create TUN %s (%v), falling back to auto-generated name", t.config.TunName, err)
	return CreateTUN("")
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

	mode := faketcp.GetMode()
	log.Printf("Using %s for firewall bypass", faketcp.ModeString(mode))

	conn, err := faketcp.DialWithMode(t.config.RemoteAddr, timeout, mode)
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
		mode := faketcp.GetMode()
		conn, err := faketcp.DialWithMode(t.config.RemoteAddr, timeout, mode)
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

	mode := faketcp.GetMode()
	log.Printf("Using %s for firewall bypass", faketcp.ModeString(mode))

	listener, err := faketcp.ListenWithMode(t.config.LocalAddr, mode)
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
func (t *Tunnel) acceptClients(listener faketcp.ListenerAdapter) {
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
func (t *Tunnel) handleClient(conn faketcp.ConnAdapter) {
	log.Printf("Client connected: %s", conn.RemoteAddr())

	client := &ClientConnection{
		conn:      conn,
		sendQueue: make(chan []byte, t.config.SendQueueSize),
		recvQueue: make(chan []byte, t.config.RecvQueueSize),
		stopCh:    make(chan struct{}),
	}

	if t.fec != nil {
		client.fecManager = NewFECManager(t.fec)
	}

	t.trackClientConnection(client)

	// Send client's public address for NAT traversal (if P2P enabled)
	if t.config.P2PEnabled {
		go t.sendPublicAddrToClient(client)
	}

	// Start client goroutines
	client.wg.Add(3)
	go t.clientNetReader(client)
	go t.clientNetWriter(client)
	go t.clientKeepalive(client)

	// Send server routes to client
	go t.sendRoutesToClient(client)

	// Wait for client to disconnect
	client.wg.Wait()

	t.untrackClientConnection(client)
	// Clean up client
	t.removeClient(client)
	log.Printf("Client disconnected: %s", conn.RemoteAddr())
}

// tunReader reads packets from TUN device and queues them for sending (client mode)
func (t *Tunnel) tunReader() {
	defer t.wg.Done()

	for {
		select {
		case <-t.stopCh:
			return
		default:
		}

		buf := t.getPacketBuffer()
		// Leave one byte headroom so prependPacketType can reuse the buffer without reallocating.
		readBuf := buf[:t.packetBufSize-1]
		n, err := t.tunFile.Read(readBuf)
		if err != nil {
			if errors.Is(err, syscall.EBADF) {
				t.releasePacketBuffer(buf)
				return
			}
			select {
			case <-t.stopCh:
				// Tunnel is stopping, no need to log
			default:
				log.Printf("TUN read error: %v", err)
			}
			t.releasePacketBuffer(buf)
			return
		}

		if n > 0 {
			// Skip packets that are too small or not IPv4
			if n < IPv4MinHeaderLen {
				t.releasePacketBuffer(buf)
				continue
			}

			// Check if packet is IPv4 (skip non-IPv4 packets like IPv6)
			if readBuf[0]>>4 != IPv4Version {
				t.releasePacketBuffer(buf)
				continue
			}

			packet := readBuf[:n]

			// Use intelligent routing if P2P is enabled
			if t.config.P2PEnabled && t.routingTable != nil {
				queued, err := t.sendPacketWithRouting(packet)
				if !queued {
					t.releasePacketBuffer(buf)
				}
				if err != nil {
					log.Printf("Failed to send packet: %v", err)
				}
			} else {
				// Default: queue for server
				if !enqueueWithTimeout(t.sendQueue, packet, t.stopCh) {
					t.releasePacketBuffer(buf)
					select {
					case <-t.stopCh:
						return
					default:
						log.Printf("Send queue full after timeout, dropping packet")
					}
				}
			}
		}
	}
}

// tunReaderServer reads packets from TUN device and routes them to clients (server mode)
func (t *Tunnel) tunReaderServer() {
	defer t.wg.Done()

	for {
		select {
		case <-t.stopCh:
			return
		default:
		}

		buf := t.getPacketBuffer()
		// Leave one byte headroom so prependPacketType can reuse the buffer without reallocating.
		readBuf := buf[:t.packetBufSize-1]
		n, err := t.tunFile.Read(readBuf)
		if err != nil {
			if errors.Is(err, syscall.EBADF) {
				t.releasePacketBuffer(buf)
				return
			}
			select {
			case <-t.stopCh:
				// Tunnel is stopping, no need to log
			default:
				log.Printf("TUN read error: %v", err)
			}
			t.releasePacketBuffer(buf)
			return
		}

		if n < IPv4MinHeaderLen {
			t.releasePacketBuffer(buf)
			continue
		}

		packet := readBuf[:n]

		// Parse destination IP from packet (IPv4)
		// IP header: version(4 bits) + IHL(4 bits) + ... + dst IP (4 bytes starting at offset 16 for IPv4)
		if packet[0]>>4 != IPv4Version {
			// Not IPv4, skip
			t.releasePacketBuffer(buf)
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
			t.releasePacketBuffer(buf)
			continue
		}

		// Enforce client isolation: if enabled, block forwarding between clients
		// This prevents packets from being forwarded from TUN back to clients
		// even if kernel routing would normally route them
		if t.config.ClientIsolation {
			// Check if destination is a registered client
			if t.getClientByIP(dstIP) != nil {
				// Drop packet - client isolation prevents client-to-client communication
				log.Printf("Client isolation: dropping packet to client %s from TUN (likely kernel route)", dstIP)
				t.releasePacketBuffer(buf)
				continue
			}
		}

		// Find the client with this destination IP
		client := t.getClientByIP(dstIP)
		if client != nil {
			select {
			case client.sendQueue <- packet:
			case <-t.stopCh:
				t.releasePacketBuffer(buf)
				return
			case <-time.After(QueueSendTimeout):
				// Wait for queue space before logging and dropping
				select {
				case client.sendQueue <- packet:
				case <-t.stopCh:
					t.releasePacketBuffer(buf)
					return
				default:
					log.Printf("⚠️  Client send queue full for %s after timeout, dropping packet", dstIP)
					t.releasePacketBuffer(buf)
				}
			}
		} else {
			// Try advertised routes
			if routeClient := t.findRouteClient(dstIP); routeClient != nil {
				select {
				case routeClient.sendQueue <- packet:
				case <-t.stopCh:
					t.releasePacketBuffer(buf)
					return
				case <-time.After(QueueSendTimeout):
					select {
					case routeClient.sendQueue <- packet:
					case <-t.stopCh:
						t.releasePacketBuffer(buf)
						return
					default:
						log.Printf("⚠️  Route client queue full for %s after timeout, dropping packet", dstIP)
						t.releasePacketBuffer(buf)
					}
				}
			} else {
				t.releasePacketBuffer(buf)
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

	// Initialize last receive time
	t.lastRecvMux.Lock()
	t.lastRecvTime = time.Now()
	t.lastRecvMux.Unlock()

	for {
		select {
		case <-t.stopCh:
			return
		default:
		}

		// Check for idle connection timeout before attempting read
		t.lastRecvMux.Lock()
		timeSinceLastRecv := time.Since(t.lastRecvTime)
		t.lastRecvMux.Unlock()

		if timeSinceLastRecv > IdleConnectionTimeout {
			log.Printf("Connection idle for %v (threshold: %v), forcing reconnection...",
				timeSinceLastRecv, IdleConnectionTimeout)

			// Close and clear current connection
			t.connMux.Lock()
			if t.conn != nil {
				_ = t.conn.Close()
				t.conn = nil
			}
			t.connMux.Unlock()

			// Reset last receive time before reconnecting
			t.lastRecvMux.Lock()
			t.lastRecvTime = time.Now()
			t.lastRecvMux.Unlock()

			// Attempt reconnection
			if err := t.reconnectToServer(); err != nil {
				// Only returns error when stopCh is closed
				return
			}

			log.Printf("Reconnection successful after idle timeout")
			t.reannounceP2PInfoAfterReconnect()
			continue
		}

		// Ensure we have a live connection
		if t.conn == nil {
			if err := t.reconnectToServer(); err != nil {
				// Only return if tunnel is explicitly stopping
				// reconnectToServer only returns error when stopCh is closed
				return
			}
			// Reset last receive time after reconnection
			t.lastRecvMux.Lock()
			t.lastRecvTime = time.Now()
			t.lastRecvMux.Unlock()
		}

		packet, err := t.conn.ReadPacket()
		if err != nil {
			// Check if it's a timeout - if so, continue to allow checking stopCh and idle timeout
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}

			select {
			case <-t.stopCh:
				// Tunnel is stopping, no need to log
				return
			default:
				log.Printf("Network read error: %v, attempting reconnection...", err)
			}

			// Close and clear current connection, then attempt reconnect
			t.connMux.Lock()
			if t.conn != nil {
				_ = t.conn.Close()
				t.conn = nil
			}
			t.connMux.Unlock()

			// Keep trying to reconnect - only exits if tunnel is stopping
			if err := t.reconnectToServer(); err != nil {
				// Only returns error when stopCh is closed
				return
			}

			// Successfully reconnected, continue reading
			log.Printf("Reconnection successful, resuming packet reception")

			// Reset last receive time after reconnection
			t.lastRecvMux.Lock()
			t.lastRecvTime = time.Now()
			t.lastRecvMux.Unlock()

			// Re-announce P2P info after reconnection to re-establish P2P connections
			t.reannounceP2PInfoAfterReconnect()

			continue
		}

		if len(packet) < 1 {
			continue
		}

		// Update last receive time for any packet received
		t.lastRecvMux.Lock()
		t.lastRecvTime = time.Now()
		t.lastRecvMux.Unlock()

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
		case PacketTypeData, PacketTypeDataPlain:
			// PacketTypeDataPlain is converted to PacketTypeData during decryption
			// Both cases queue for TUN device
			if !enqueueWithTimeout(t.recvQueue, payload, t.stopCh) {
				select {
				case <-t.stopCh:
					return
				default:
					log.Printf("Receive queue full after timeout, dropping packet")
				}
			}
		case PacketTypeFEC:
			if t.fecManager != nil {
				if len(payload) < 8 {
					continue
				}
				packetID := binary.BigEndian.Uint32(payload[0:4])
				shardIdx := int(payload[4])
				totalShards := int(payload[5])
				origLen := int(binary.BigEndian.Uint16(payload[6:8]))
				shardData := payload[8:]

				reconstructed := t.fecManager.AddShard(packetID, shardIdx, totalShards, origLen, shardData)
				if reconstructed != nil {
					if !enqueueWithTimeout(t.recvQueue, reconstructed, t.stopCh) {
						select {
						case <-t.stopCh:
							return
						default:
							log.Printf("Receive queue full after timeout, dropping reconstructed packet")
						}
					}
				}
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

			// Detect NAT type if enabled and announce peer info after detection
			if t.config.EnableNATDetection && t.p2pManager != nil {
				go func() {
					// Perform NAT detection
					t.p2pManager.DetectNATType(t.config.RemoteAddr)
					
					// After NAT detection completes, announce peer info to server
					// Retry with exponential backoff to ensure it gets through
					log.Printf("NAT detection complete, announcing peer info to server")
					
					maxRetries := 5
					for attempt := 0; attempt < maxRetries; attempt++ {
						if err := t.announcePeerInfo(); err != nil {
							log.Printf("Failed to announce peer info (attempt %d/%d): %v", attempt+1, maxRetries, err)
							// Exponential backoff: 1s, 2s, 4s, 8s, 16s
							backoff := exponentialBackoff(attempt, 1*time.Second)
							time.Sleep(backoff)
						} else {
							log.Printf("Successfully announced peer info to server on attempt %d", attempt+1)
							break
						}
					}
				}()
			} else if t.config.P2PEnabled && t.p2pManager != nil {
				// If NAT detection is disabled but P2P is enabled, announce immediately with retry
				go func() {
					// Wait a bit for connection to stabilize
					time.Sleep(1 * time.Second)
					log.Printf("P2P enabled without NAT detection, announcing peer info to server")
					
					maxRetries := 5
					for attempt := 0; attempt < maxRetries; attempt++ {
						if err := t.announcePeerInfo(); err != nil {
							log.Printf("Failed to announce peer info (attempt %d/%d): %v", attempt+1, maxRetries, err)
							backoff := exponentialBackoff(attempt, 1*time.Second)
							time.Sleep(backoff)
						} else {
							log.Printf("Successfully announced peer info to server on attempt %d", attempt+1)
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
		case PacketTypeRouteInfo:
			t.handleRouteInfoPayload(payload)
		case PacketTypeConfigUpdate:
			t.handleConfigUpdate(payload)
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
			func() {
				defer t.releasePacketBuffer(packet)

				// Use FEC if enabled
				if t.fecManager != nil {
					packetID := atomic.AddUint32(&t.nextPacketID, 1)
					shards, err := t.fecManager.EncodePacket(packetID, packet)
					if err == nil {
						for _, shard := range shards {
							encryptedShard, err := t.encryptPacket(shard)
							if err != nil {
								continue
							}
							if t.conn != nil {
								// Best effort for shards
								_ = t.conn.WritePacket(encryptedShard)
							}
						}
						return
					}
				}

				fullPacket, _ := prependPacketType(packet, PacketTypeData)

				// Encrypt if cipher is available
				encryptedPacket, err := t.encryptPacket(fullPacket)
				if err != nil {
					log.Printf("Encryption error: %v", err)
					return
				}

				// Ensure we have a live connection before writing
				if t.conn == nil {
					if err := t.reconnectToServer(); err != nil {
						// Only returns error when stopCh is closed
						return
					}
				}

				if err := t.conn.WritePacket(encryptedPacket); err != nil {
					select {
					case <-t.stopCh:
						// Tunnel is stopping, no need to log
						return
					default:
						log.Printf("Network write error: %v, attempting reconnection...", err)
					}

					// Close and clear connection then try to reconnect
					t.connMux.Lock()
					if t.conn != nil {
						_ = t.conn.Close()
						t.conn = nil
					}
					t.connMux.Unlock()

					// Keep trying to reconnect - only exits if tunnel is stopping
					if err := t.reconnectToServer(); err != nil {
						// Only returns error when stopCh is closed
						return
					}

					// Try writing once more after reconnect
					log.Printf("Reconnection successful, retrying packet send")

					// Re-announce P2P info after reconnection to re-establish P2P connections
					t.reannounceP2PInfoAfterReconnect()

					if t.conn != nil {
						if err2 := t.conn.WritePacket(encryptedPacket); err2 != nil {
							log.Printf("Network write retry failed: %v, packet will be lost", err2)
							// Don't return - continue processing queue
							// Accept packet loss to maintain tunnel connectivity for subsequent packets.
							// This is better than exiting the goroutine, which would prevent any future
							// packets from being sent even after the connection is restored.
						}
					}
				}
			}()
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
					// Only returns error when stopCh is closed
					return
				}
			}

			if err := t.conn.WritePacket(encryptedPacket); err != nil {
				select {
				case <-t.stopCh:
					// Tunnel is stopping, no need to log
					return
				default:
					log.Printf("Keepalive error: %v, attempting reconnection...", err)
				}

				// Close and clear connection then attempt reconnect
				t.connMux.Lock()
				if t.conn != nil {
					_ = t.conn.Close()
					t.conn = nil
				}
				t.connMux.Unlock()

				// Keep trying to reconnect - only exits if tunnel is stopping
				if err := t.reconnectToServer(); err != nil {
					// Only returns error when stopCh is closed
					return
				}

				log.Printf("Reconnection successful, keepalive will resume")

				// Re-announce P2P info after reconnection to re-establish P2P connections
				t.reannounceP2PInfoAfterReconnect()

				// Don't return; let loop continue with the next tick
			}
		}
	}
}

// clientNetReader reads packets from a client connection
func (t *Tunnel) clientNetReader(client *ClientConnection) {
	defer client.wg.Done()

	// Initialize last receive time
	client.mu.Lock()
	client.lastRecvTime = time.Now()
	client.mu.Unlock()

	for {
		select {
		case <-t.stopCh:
			return
		case <-client.stopCh:
			return
		default:
		}

		// Check for idle connection timeout
		client.mu.RLock()
		timeSinceLastRecv := time.Since(client.lastRecvTime)
		client.mu.RUnlock()

		if timeSinceLastRecv > IdleConnectionTimeout {
			log.Printf("Client connection from %s idle for %v (threshold: %v), closing...",
				client.conn.RemoteAddr(), timeSinceLastRecv, IdleConnectionTimeout)
			client.stopOnce.Do(func() {
				close(client.stopCh)
			})
			return
		}

		packet, err := client.conn.ReadPacket()
		if err != nil {
			// Check if it's a timeout - if so, continue to allow checking stopCh and idle timeout
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

		// Update last receive time for any packet received
		client.mu.Lock()
		client.lastRecvTime = time.Now()
		client.mu.Unlock()

		// Decrypt if cipher is available (supports previous key during grace)
		decryptedPacket, usedCipher, gen, err := t.decryptPacketForServer(packet)
		if err != nil {
			log.Printf("Client decryption error from %s (wrong key?): %v", client.conn.RemoteAddr(), err)
			continue
		}

		if usedCipher != nil {
			client.setCipherWithGen(usedCipher, gen)
		}

		if len(decryptedPacket) < 1 {
			continue
		}

		// Check packet type
		packetType := decryptedPacket[0]
		payload := decryptedPacket[1:]

		switch packetType {
		case PacketTypeData, PacketTypeDataPlain:
			// PacketTypeDataPlain is converted to PacketTypeData during decryption
			if len(payload) < IPv4MinHeaderLen {
				continue
			}
			t.routePacket(client, payload)

		case PacketTypeFEC:
			if client.fecManager != nil {
				if len(payload) < 8 {
					continue
				}
				packetID := binary.BigEndian.Uint32(payload[0:4])
				shardIdx := int(payload[4])
				totalShards := int(payload[5])
				origLen := int(binary.BigEndian.Uint16(payload[6:8]))
				shardData := payload[8:]

				reconstructed := client.fecManager.AddShard(packetID, shardIdx, totalShards, origLen, shardData)
				if reconstructed != nil {
					if len(reconstructed) >= IPv4MinHeaderLen {
						t.routePacket(client, reconstructed)
					}
				}
			}

		case PacketTypeKeepalive:
			// Keepalive received, no action needed
		case PacketTypePeerInfo:
			// Handle peer info from client (server mode) - store but don't broadcast
			if t.config.P2PEnabled {
				peerInfoStr := string(payload)
				log.Printf("Received and stored peer info from client: %s", peerInfoStr)

				// Parse peer info to get tunnel IP
				parts := strings.Split(peerInfoStr, "|")
				if len(parts) >= 3 {
					tunnelIP := net.ParseIP(parts[0])
					if tunnelIP != nil {
						// Register client if not yet registered
						if client.clientIP == nil {
							t.addClient(client, tunnelIP)
						}

						// Store peer info for on-demand P2P connection establishment
						// No automatic broadcast - connections established only when needed
						client.mu.Lock()
						client.lastPeerInfo = peerInfoStr
						client.mu.Unlock()
						log.Printf("Stored peer info for %s, ready for on-demand P2P", tunnelIP)
					}
				}
			}
		case PacketTypeP2PRequest:
			// Handle P2P connection request from client (server mode)
			t.handleP2PRequest(client, payload)
		case PacketTypeRouteInfo:
			// Register routes advertised by client and respond with server routes
			routes := parseRouteList(string(payload))
			if len(routes) > 0 {
				t.registerClientRoutes(client, routes)
				go t.sendRoutesToClient(client)
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
			func() {
				defer t.releasePacketBuffer(packet)

				// Use FEC if enabled
				if client.fecManager != nil {
					packetID := atomic.AddUint32(&client.nextPacketID, 1)
					shards, err := client.fecManager.EncodePacket(packetID, packet)
					if err == nil {
						for _, shard := range shards {
							encryptedShard, err := t.encryptForClient(client, shard)
							if err != nil {
								continue
							}
							_ = client.conn.WritePacket(encryptedShard)
						}
						return
					}
				}

				fullPacket, _ := prependPacketType(packet, PacketTypeData)

				// Encrypt if cipher is available
				encryptedPacket, err := t.encryptForClient(client, fullPacket)
				if err != nil {
					log.Printf("Client encryption error: %v", err)
					return
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
				}
			}()
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
			encryptedPacket, err := t.encryptForClient(client, keepalivePacket)
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
	// Format: TunnelIP|PublicAddr|LocalAddr|NATType|timestamp_ms
	// The timestamp_ms (if present) indicates coordinated punch time for symmetric NAT
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
	
	// Parse coordination timestamp if available (5th parameter) for symmetric NAT
	// Maximum delay for timing coordination (milliseconds)
	// Prevents unreasonably long waits from malformed packets
	const maxPunchDelayMs = 5000
	var punchDelay time.Duration
	if len(parts) >= 5 {
		var targetTimestamp int64
		if _, err := fmt.Sscanf(parts[4], "%d", &targetTimestamp); err == nil {
			now := time.Now().UnixMilli()
			delay := targetTimestamp - now
			if delay > 0 && delay < maxPunchDelayMs {
				punchDelay = time.Duration(delay) * time.Millisecond
				log.Printf("PUNCH for %s: coordinated start in %dms", tunnelIP, delay)
			}
		}
	}

	// Add to routing table first
	if t.routingTable != nil {
		t.routingTable.AddPeer(peer)
	}

	// Then add to P2P manager and attempt connection with timing coordination
	// PUNCH messages indicate both sides should attempt simultaneously
	if t.p2pManager != nil {
		t.p2pManager.AddPeer(peer)

		// Check if P2P is feasible
		if !t.p2pManager.CanEstablishP2PWith(tunnelIP) {
			log.Printf("PUNCH received for %s but P2P not feasible (both Symmetric NAT)", tunnelIP)
			return
		}

		go func() {
			// Wait for coordinated timing if specified (symmetric NAT optimization)
			if punchDelay > 0 {
				time.Sleep(punchDelay)
			}
			
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

// getAdvertisedRoutes returns unique routes to announce.
func (t *Tunnel) getAdvertisedRoutes() []string {
	routeSet := make(map[string]struct{})
	t.configMux.RLock()
	for _, r := range t.config.Routes {
		if r != "" {
			routeSet[r] = struct{}{}
		}
	}
	if t.config.TunnelAddr != "" {
		routeSet[t.config.TunnelAddr] = struct{}{}
	}
	t.configMux.RUnlock()

	routes := make([]string, 0, len(routeSet))
	for r := range routeSet {
		routes = append(routes, r)
	}
	return routes
}

func parseRouteList(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	routes := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			routes = append(routes, p)
		}
	}
	return routes
}

// routeAdvertLoop periodically advertises routes to the server (client mode).
func (t *Tunnel) routeAdvertLoop() {
	defer t.wg.Done()

	if len(t.getAdvertisedRoutes()) == 0 {
		return
	}

	// Send immediately once connected
	t.sendRoutesToServer()

	// Use RouteAdvertInterval from config, which defaults to 300 seconds (5 minutes)
	interval := time.Duration(t.config.RouteAdvertInterval) * time.Second
	if t.config.RouteUpdateInterval > 0 {
		// RouteUpdateInterval overrides if set (for backward compatibility)
		interval = time.Duration(t.config.RouteUpdateInterval) * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-t.stopCh:
			return
		case <-ticker.C:
			t.sendRoutesToServer()
		}
	}
}

func (t *Tunnel) sendRoutesToServer() {
	routes := t.getAdvertisedRoutes()
	if len(routes) == 0 {
		return
	}

	// Ensure connection exists
	t.connMux.Lock()
	conn := t.conn
	t.connMux.Unlock()

	if conn == nil {
		if err := t.reconnectToServer(); err != nil {
			return
		}
		t.connMux.Lock()
		conn = t.conn
		t.connMux.Unlock()
		if conn == nil {
			return
		}
	}

	if err := t.sendRoutePacket(conn, routes); err != nil {
		log.Printf("Failed to send routes to server: %v", err)
	}
}

func (t *Tunnel) sendRoutesToClient(client *ClientConnection) {
	if client == nil {
		return
	}
	routes := t.getAdvertisedRoutes()
	if len(routes) == 0 {
		return
	}
	payload := strings.Join(routes, ",")
	fullPacket := make([]byte, len(payload)+1)
	fullPacket[0] = PacketTypeRouteInfo
	copy(fullPacket[1:], []byte(payload))

	encryptedPacket, err := t.encryptForClient(client, fullPacket)
	if err != nil {
		log.Printf("Failed to encrypt routes for client: %v", err)
		return
	}

	if err := client.conn.WritePacket(encryptedPacket); err != nil {
		log.Printf("Failed to send routes to client: %v", err)
	}
}

func (t *Tunnel) sendRoutePacket(conn faketcp.ConnAdapter, routes []string) error {
	if conn == nil {
		return fmt.Errorf("no connection available")
	}
	payload := strings.Join(routes, ",")
	fullPacket := make([]byte, len(payload)+1)
	fullPacket[0] = PacketTypeRouteInfo
	copy(fullPacket[1:], []byte(payload))

	encryptedPacket, err := t.encryptPacket(fullPacket)
	if err != nil {
		return err
	}

	return conn.WritePacket(encryptedPacket)
}

// handleRouteInfoPayload applies routes received from the peer.
func (t *Tunnel) handleRouteInfoPayload(data []byte) {
	routes := parseRouteList(string(data))
	for _, route := range routes {
		if err := t.addRoute(route); err != nil {
			log.Printf("Failed to apply route %s: %v", route, err)
		} else {
			log.Printf("Applied peer route %s via %s", route, t.tunName)
		}
	}
}

func (t *Tunnel) registerClientRoutes(client *ClientConnection, routes []string) {
	if client == nil || len(routes) == 0 {
		return
	}

	t.routeMux.Lock()
	// Remove old entries for this client
	t.removeClientRoutesLocked(client, false)

	for _, route := range routes {
		_, ipNet, err := net.ParseCIDR(route)
		if err != nil {
			log.Printf("Invalid advertised route %s: %v", route, err)
			continue
		}
		t.advertisedRoutes = append(t.advertisedRoutes, clientRoute{
			network: ipNet,
			client:  client,
		})
		t.clientRoutes[client] = append(t.clientRoutes[client], route)
	}
	t.routeMux.Unlock()

	// Apply routes to local OS
	for _, route := range routes {
		if err := t.addRoute(route); err != nil {
			log.Printf("Failed to install client route %s: %v", route, err)
		}
	}
}

func (t *Tunnel) findRouteClient(dstIP net.IP) *ClientConnection {
	t.routeMux.RLock()
	defer t.routeMux.RUnlock()
	for _, entry := range t.advertisedRoutes {
		if entry.network.Contains(dstIP) {
			return entry.client
		}
	}
	return nil
}

func (t *Tunnel) cleanupClientRoutes(client *ClientConnection) {
	t.routeMux.Lock()
	defer t.routeMux.Unlock()
	t.removeClientRoutesLocked(client, true)
}

func (t *Tunnel) removeClientRoutesLocked(client *ClientConnection, deleteOS bool) {
	// Filter advertisedRoutes
	filtered := t.advertisedRoutes[:0]
	for _, entry := range t.advertisedRoutes {
		if entry.client != client {
			filtered = append(filtered, entry)
		}
	}
	t.advertisedRoutes = filtered

	// Remove from map
	if routes, ok := t.clientRoutes[client]; ok {
		if deleteOS {
			for _, r := range routes {
				t.deleteRoute(r)
			}
		}
		delete(t.clientRoutes, client)
	}
}

func (t *Tunnel) addRoute(route string) error {
	if route == "" || t.tunName == "" {
		return nil
	}
	if !isSafeTunName(t.tunName) {
		return fmt.Errorf("unsafe tun device name")
	}
	_, ipNet, err := net.ParseCIDR(route)
	if err != nil {
		return fmt.Errorf("invalid route %s: %w", route, err)
	}
	route = ipNet.String()

	cmd := exec.Command("ip", "route", "replace", route, "dev", t.tunName)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v (output: %s)", err, output)
	}
	return nil
}

func (t *Tunnel) deleteRoute(route string) {
	if route == "" || t.tunName == "" {
		return
	}
	if !isSafeTunName(t.tunName) {
		return
	}
	_, ipNet, err := net.ParseCIDR(route)
	if err != nil {
		return
	}
	route = ipNet.String()

	cmd := exec.Command("ip", "route", "del", route, "dev", t.tunName)
	_, _ = cmd.CombinedOutput()
}

// sendPacketWithRouting sends a packet using intelligent routing
// Returns true when the packet is queued to the server send queue.
func (t *Tunnel) sendPacketWithRouting(packet []byte) (bool, error) {
	if len(packet) < IPv4MinHeaderLen {
		return false, errors.New("packet too small")
	}

	// Parse destination IP
	if packet[0]>>4 != IPv4Version {
		return false, errors.New("not IPv4 packet")
	}

	dstIP := net.IP(packet[IPv4DstIPOffset : IPv4DstIPOffset+4])

	// On-demand P2P: Check if we have a P2P connection
	if t.p2pManager != nil && t.p2pManager.IsConnected(dstIP) {
		// Direct P2P connection exists, use it
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
			return t.sendViaServer(packet)
		}
		return false, nil
	}

	// No P2P connection - try to establish one on-demand
	if t.config.P2PEnabled && t.p2pManager != nil {
		// Check if we should request P2P connection
		if t.shouldRequestP2P(dstIP) {
			// Send P2P request to server
			t.requestP2PConnection(dstIP)
		}
	}

	// For now, send via server (P2P will be established for future packets)
	return t.sendViaServer(packet)
}

// shouldRequestP2P checks if we should request a P2P connection to the target IP
// Returns false if a request is already pending or was recently made
func (t *Tunnel) shouldRequestP2P(targetIP net.IP) bool {
	// Never request P2P to the server itself
	if t.serverTunnelIP != nil && targetIP.Equal(t.serverTunnelIP) {
		return false
	}
	
	targetIPStr := targetIP.String()
	
	t.p2pRequestMux.Lock()
	defer t.p2pRequestMux.Unlock()
	
	// Check if request already pending
	if lastReq, exists := t.pendingP2PRequests[targetIPStr]; exists {
		// Allow retry after 10 seconds if P2P hasn't been established
		// This gives time for peer info to be announced and processed
		if time.Since(lastReq) < 10*time.Second {
			return false
		}
		// Check if P2P is actually connected now before retrying
		if t.p2pManager != nil && t.p2pManager.IsConnected(targetIP) {
			// P2P established, no need to request again
			delete(t.pendingP2PRequests, targetIPStr)
			return false
		}
		// P2P not established after 10s, allow retry
		log.Printf("P2P request for %s timed out after 10s, will retry", targetIPStr)
	}
	
	return true
}

// requestP2PConnection sends a P2P connection request to the server
func (t *Tunnel) requestP2PConnection(targetIP net.IP) {
	targetIPStr := targetIP.String()
	
	// Mark as pending
	t.p2pRequestMux.Lock()
	t.pendingP2PRequests[targetIPStr] = time.Now()
	t.p2pRequestMux.Unlock()
	
	// Build request message: format is just the target tunnel IP
	payload := []byte(targetIPStr)
	fullPacket := make([]byte, len(payload)+1)
	fullPacket[0] = PacketTypeP2PRequest
	copy(fullPacket[1:], payload)
	
	// Encrypt and send
	encryptedPacket, err := t.encryptPacket(fullPacket)
	if err != nil {
		log.Printf("Failed to encrypt P2P request: %v", err)
		return
	}
	
	// Send to server with retry logic
	maxRetries := 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		t.connMux.Lock()
		conn := t.conn
		t.connMux.Unlock()
		
		if conn != nil {
			if err := conn.WritePacket(encryptedPacket); err != nil {
				log.Printf("Failed to send P2P request to server (attempt %d/%d): %v", attempt+1, maxRetries, err)
				if attempt < maxRetries-1 {
					backoff := exponentialBackoff(attempt, 1*time.Second)
					time.Sleep(backoff)
				}
			} else {
				log.Printf("Sent P2P connection request for %s to server", targetIPStr)
				return
			}
		} else {
			log.Printf("No connection available to send P2P request (attempt %d/%d)", attempt+1, maxRetries)
			if attempt < maxRetries-1 {
				backoff := exponentialBackoff(attempt, 1*time.Second)
				time.Sleep(backoff)
			}
		}
	}
	
	log.Printf("Failed to send P2P request after %d attempts", maxRetries)
}

// sendViaServer sends packet through the server connection
// Uses timeout-based approach to handle queue congestion
func (t *Tunnel) sendViaServer(packet []byte) (bool, error) {
	select {
	case t.sendQueue <- packet:
		return true, nil
	case <-t.stopCh:
		return false, errors.New("tunnel stopped")
	case <-time.After(QueueSendTimeout):
		// Wait for queue space before giving up
		// This handles temporary bursts without immediately dropping packets
		select {
		case t.sendQueue <- packet:
			return true, nil
		case <-t.stopCh:
			return false, errors.New("tunnel stopped")
		default:
			return false, errors.New("send queue full after timeout")
		}
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

// exponentialBackoff calculates exponential backoff delay with a maximum cap
// Returns delay = baseDelay * 2^attempt, capped at 32 seconds
func exponentialBackoff(attempt int, baseDelay time.Duration) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	// Cap attempt at 5 to prevent overflow (2^5 = 32)
	if attempt > 5 {
		attempt = 5
	}
	multiplier := 1 << uint(attempt) // Safe: attempt is capped at 5, so max is 2^5 = 32
	return baseDelay * time.Duration(multiplier)
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

func applyKernelTunings(enabled bool) {
	if !enabled {
		return
	}
	// Enable TCP Fast Open for client+server (3)
	if err := runSysctl("net.ipv4.tcp_fastopen=3"); err != nil {
		log.Printf("⚠️  Failed to enable TCP Fast Open: %v", err)
	} else {
		log.Println("TCP Fast Open enabled (net.ipv4.tcp_fastopen=3)")
	}

	// fq qdisc is recommended for BBR/BBR2 to pace traffic correctly.
	if err := runSysctl("net.core.default_qdisc=fq"); err != nil {
		log.Printf("⚠️  Failed to set default qdisc to fq: %v", err)
	} else {
		log.Println("fq qdisc enabled (net.core.default_qdisc=fq)")
	}

	// Prefer BBR2 congestion control if available; fallback silently if kernel lacks it.
	if err := runSysctl("net.ipv4.tcp_congestion_control=bbr2"); err != nil {
		log.Printf("⚠️  Failed to set BBR2 congestion control (kernel may not support bbr2): %v", err)
		// Fallback to BBR if BBR2 is unavailable.
		if err := runSysctl("net.ipv4.tcp_congestion_control=bbr"); err != nil {
			log.Printf("⚠️  Failed to fallback to BBR congestion control: %v", err)
		} else {
			log.Println("BBR congestion control enabled (fallback from bbr2)")
		}
	} else {
		log.Println("BBR2 congestion control enabled")
	}
}

func runSysctl(setting string) error {
	cmd := exec.Command("sysctl", "-w", setting)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v (output: %s)", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (t *Tunnel) shouldSkipOuterEncryption(data []byte) bool {
	if len(data) < 1 {
		return false
	}
	
	// Only check PacketTypeData, not PacketTypeDataPlain
	// PacketTypeDataPlain is explicitly for plaintext passthrough
	if data[0] != PacketTypeData {
		return false
	}

	classifier := func(pkt []byte) bool {
		return isLikelyEncryptedTraffic(pkt)
	}
	ipPacket := data[1:]
	if t.xdpAccel != nil {
		return t.xdpAccel.Classify(ipPacket, classifier)
	}
	return classifier(ipPacket)
}

// encryptPacket encrypts a packet if cipher is available
func (t *Tunnel) encryptPacket(data []byte) ([]byte, error) {
	t.cipherMux.RLock()
	c := t.cipher
	t.cipherMux.RUnlock()
	if c == nil {
		return data, nil
	}
	if t.shouldSkipOuterEncryption(data) {
		// Change packet type to PacketTypeDataPlain to indicate plaintext passthrough
		// This prevents the receiver from attempting decryption on already-encrypted traffic
		if len(data) > 0 && data[0] == PacketTypeData {
			data[0] = PacketTypeDataPlain
		}
		return data, nil
	}
	return c.Encrypt(data)
}

func (t *Tunnel) decryptWithFallback(data []byte) ([]byte, *crypto.Cipher, uint64, error) {
	// Check if this is plaintext passthrough (encrypted-only traffic like HTTPS)
	if len(data) > 0 && data[0] == PacketTypeDataPlain {
		// Change back to PacketTypeData for processing
		data[0] = PacketTypeData
		return data, nil, 0, nil
	}

	t.cipherMux.RLock()
	active := t.cipher
	activeGen := t.cipherGen
	prev := t.prevCipher
	prevGen := t.prevCipherGen
	exp := t.prevCipherExp
	t.cipherMux.RUnlock()

	var activeErr error
	if active != nil {
		if plain, err := active.Decrypt(data); err == nil {
			if prev != nil && t.isPrevCipherActive(prev) {
				t.deactivatePrevCipher(prev, "new key confirmed in use")
			}
			return plain, active, activeGen, nil
		} else {
			activeErr = err
		}
	}

	if prev != nil {
		if time.Now().After(exp) && t.isPrevCipherActive(prev) {
			t.deactivatePrevCipher(prev, "grace period expired")
		} else if plain, err := prev.Decrypt(data); err == nil {
			return plain, prev, prevGen, nil
		}
	}

	if activeErr != nil {
		return nil, nil, 0, activeErr
	}
	return nil, nil, 0, errors.New("decryption failed")
}

// decryptPacket decrypts a packet if cipher is available
func (t *Tunnel) decryptPacket(data []byte) ([]byte, error) {
	plain, _, _, err := t.decryptWithFallback(data)
	return plain, err
}

func (t *Tunnel) decryptPacketForServer(data []byte) ([]byte, *crypto.Cipher, uint64, error) {
	return t.decryptWithFallback(data)
}

func (t *Tunnel) encryptForClient(client *ClientConnection, data []byte) ([]byte, error) {
	if t.shouldSkipOuterEncryption(data) {
		// Change packet type to PacketTypeDataPlain to indicate plaintext passthrough
		if len(data) > 0 && data[0] == PacketTypeData {
			data[0] = PacketTypeDataPlain
		}
		return data, nil
	}
	if client != nil {
		if c, _ := client.getCipher(); c != nil {
			return c.Encrypt(data)
		}
	}
	return t.encryptPacket(data)
}

func (t *Tunnel) isPrevCipherActive(prev *crypto.Cipher) bool {
	t.cipherMux.RLock()
	defer t.cipherMux.RUnlock()
	return prev != nil && t.prevCipher == prev
}

func (t *Tunnel) deactivatePrevCipher(prev *crypto.Cipher, reason string) {
	if prev == nil {
		return
	}

	t.cipherMux.Lock()
	if t.prevCipher != prev {
		t.cipherMux.Unlock()
		return
	}
	t.prevCipher = nil
	t.prevCipherGen = 0
	t.prevCipherExp = time.Time{}
	t.cipherMux.Unlock()

	log.Printf("Deactivated previous cipher (%s)", reason)
}

// registerServerPeer seeds the routing table with the server endpoint so stats
// are meaningful even before peer info is exchanged.
func (t *Tunnel) registerServerPeer() {
	serverTunnel, err := GetPeerIP(t.config.TunnelAddr)
	if err != nil {
		log.Printf("Failed to derive server tunnel IP: %v", err)
		return
	}
	parts := strings.Split(serverTunnel, "/")
	if len(parts) == 0 {
		return
	}
	ip := net.ParseIP(parts[0])
	if ip == nil {
		return
	}

	peer := p2p.NewPeerInfo(ip)
	peer.SetThroughServer(true)
	t.routingTable.AddPeer(peer)
}

// rotateCipher replaces the active cipher and config key.
func (t *Tunnel) rotateCipher(newKey string) error {
	if newKey == "" {
		return errors.New("new key is empty")
	}
	if len(newKey) < 16 {
		return errors.New("new key must be at least 16 characters")
	}
	newCipher, err := crypto.NewCipher(newKey)
	if err != nil {
		return err
	}
	t.configMux.Lock()
	t.config.Key = newKey
	t.configMux.Unlock()

	t.cipherMux.Lock()
	oldCipher := t.cipher
	oldGen := t.cipherGen
	t.cipher = newCipher
	t.cipherGen++
	if oldCipher != nil {
		t.prevCipher = oldCipher
		t.prevCipherGen = oldGen
		t.prevCipherExp = time.Now().Add(KeyRotationGracePeriod)
	} else {
		t.prevCipher = nil
		t.prevCipherGen = 0
		t.prevCipherExp = time.Time{}
	}
	t.cipherMux.Unlock()

	if oldCipher != nil {
		go t.expirePrevCipher(oldCipher)
	}

	t.persistKeyToConfigFile(newKey)
	return nil
}

func (t *Tunnel) persistKeyToConfigFile(newKey string) {
	path := t.configFilePath
	if path == "" {
		return
	}

	if err := config.UpdateConfigKey(path, newKey); err != nil {
		log.Printf("Failed to update config file with new key: %v", err)
		return
	}

	log.Printf("Updated config file (%s) with rotated key", filepath.Base(path))
}

func (t *Tunnel) expirePrevCipher(prev *crypto.Cipher) {
	timer := time.NewTimer(KeyRotationGracePeriod)
	defer timer.Stop()
	select {
	case <-timer.C:
		t.deactivatePrevCipher(prev, "grace period expired")
	case <-t.stopCh:
	}
}

// reannounceP2PInfoAfterReconnect re-announces P2P info after reconnection with retry logic
func (t *Tunnel) reannounceP2PInfoAfterReconnect() {
	if !t.config.P2PEnabled || t.p2pManager == nil {
		return
	}

	go func() {
		// Wait for public address to be received again after reconnection
		time.Sleep(P2PReconnectPublicAddrWaitTime)

		retries := 0
		for retries < P2PMaxRetries {
			if err := t.announcePeerInfo(); err != nil {
				log.Printf("Failed to re-announce P2P info after reconnection (attempt %d/%d): %v",
					retries+1, P2PMaxRetries, err)
				retries++
				backoffSeconds := 1 << uint(retries)
				if backoffSeconds > P2PMaxBackoffSeconds {
					backoffSeconds = P2PMaxBackoffSeconds
				}
				time.Sleep(time.Duration(backoffSeconds) * time.Second)
			} else {
				log.Printf("Successfully re-announced P2P info after reconnection")
				break
			}
		}
	}()
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

// retryAnnouncePeerInfo retries announcing peer info with exponential backoff
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
	encryptedPacket, err := t.encryptForClient(client, fullPacket)
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

// configPushLoop periodically sends new configuration (rotated key) to clients (server mode).
func (t *Tunnel) configPushLoop() {
	defer t.wg.Done()

	ticker := time.NewTicker(time.Duration(t.config.ConfigPushInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-t.stopCh:
			return
		case <-ticker.C:
			if err := t.pushConfigUpdate(); err != nil {
				log.Printf("Failed to push config update: %v", err)
			}
		}
	}
}

func (t *Tunnel) pushConfigUpdate() error {
	if t.config.Mode != "server" || t.cipher == nil {
		return nil
	}

	newKey, err := generateRandomKey()
	if err != nil {
		return fmt.Errorf("failed to generate new key: %w", err)
	}

	msg := ConfigUpdateMessage{
		Key:    newKey,
		Routes: t.getAdvertisedRoutes(),
	}

	payload, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal config update: %w", err)
	}

	fullPacket := make([]byte, len(payload)+1)
	fullPacket[0] = PacketTypeConfigUpdate
	copy(fullPacket[1:], payload)

	// Snapshot clients to avoid holding lock during network IO
	t.allClientsMux.RLock()
	clients := make([]*ClientConnection, 0, len(t.allClients))
	for c := range t.allClients {
		clients = append(clients, c)
	}
	t.allClientsMux.RUnlock()

	for _, client := range clients {
		if client == nil {
			continue
		}
		encryptedPacket, err := t.encryptForClient(client, fullPacket)
		if err != nil {
			log.Printf("Failed to encrypt config update for client: %v", err)
			continue
		}
		if err := client.conn.WritePacket(encryptedPacket); err != nil {
			log.Printf("Failed to send config update to client: %v", err)
		}
	}

	// Rotate server cipher while keeping existing connections. The previous cipher
	// remains active for the grace period, allowing in-flight packets from
	// clients that have not yet switched keys to be decrypted seamlessly.
	if err := t.rotateCipher(newKey); err != nil {
		return fmt.Errorf("failed to rotate cipher: %w", err)
	}

	log.Printf("Rotated tunnel key and pushed new config to %d client(s)", len(clients))

	return nil
}

// handleConfigUpdate applies server-pushed configuration (client mode).
func (t *Tunnel) handleConfigUpdate(payload []byte) {
	var msg ConfigUpdateMessage
	if err := json.Unmarshal(payload, &msg); err != nil {
		log.Printf("Failed to parse config update: %v", err)
		return
	}

	if msg.Key == "" {
		log.Printf("Received config update without key, ignoring")
		return
	}

	log.Printf("Received config update with new key; rotating cipher without reconnect...")

	if len(msg.Routes) > 0 {
		t.configMux.Lock()
		t.config.Routes = msg.Routes
		t.configMux.Unlock()
		t.handleRouteInfoPayload([]byte(strings.Join(msg.Routes, ",")))
	}

	if err := t.rotateCipher(msg.Key); err != nil {
		log.Printf("Failed to apply new key: %v", err)
		return
	}

}

func generateRandomKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// handleP2PRequest handles on-demand P2P connection requests from clients (server mode)
func (t *Tunnel) handleP2PRequest(requestingClient *ClientConnection, payload []byte) {
	if !t.config.P2PEnabled {
		return
	}
	
	// Parse target IP from request
	targetIPStr := string(payload)
	targetIP := net.ParseIP(targetIPStr)
	if targetIP == nil {
		log.Printf("Invalid P2P request: bad target IP %s", targetIPStr)
		return
	}
	
	// Reject P2P requests targeting the server itself
	if targetIP.Equal(t.myTunnelIP) {
		log.Printf("P2P request for server IP %s rejected (server should not use P2P)", targetIPStr)
		return
	}
	
	// Get requesting client's IP
	requestingClient.mu.RLock()
	requestingIP := requestingClient.clientIP
	requestingPeerInfo := requestingClient.lastPeerInfo
	requestingClient.mu.RUnlock()
	
	if requestingIP == nil {
		log.Printf("P2P request from unregistered client, ignoring")
		return
	}
	
	// Find target client
	targetClient := t.getClientByIP(targetIP)
	if targetClient == nil {
		log.Printf("P2P request for unknown target %s, ignoring", targetIPStr)
		return
	}
	
	// Get target client's peer info
	targetClient.mu.RLock()
	targetPeerInfo := targetClient.lastPeerInfo
	targetClient.mu.RUnlock()
	
	// Check if peer info is available
	if requestingPeerInfo == "" || targetPeerInfo == "" {
		log.Printf("P2P request but peer info not available (requesting=%v, target=%v)",
			requestingPeerInfo == "", targetPeerInfo == "")
		
		// Instead of waiting asynchronously, reject the request immediately
		// The client will retry when it receives traffic destined for the target
		// This prevents accumulating stale requests and hanging goroutines
		return
	}
	
	log.Printf("Processing P2P request: %s wants to connect to %s", requestingIP, targetIP)
	
	// Process the P2P connection with peer info
	t.processP2PConnection(requestingClient, targetClient, requestingPeerInfo, targetPeerInfo)
}

// processP2PConnection handles the actual P2P connection setup logic
// Extracted to avoid code duplication between immediate and delayed processing
func (t *Tunnel) processP2PConnection(requestingClient, targetClient *ClientConnection, requestingPeerInfo, targetPeerInfo string) {
	// Get client IPs for logging
	requestingClient.mu.RLock()
	requestingIP := requestingClient.clientIP
	requestingClient.mu.RUnlock()
	
	targetClient.mu.RLock()
	targetIP := targetClient.clientIP
	targetClient.mu.RUnlock()
	
	// Parse NAT types from peer info
	requestingNAT := t.parseNATTypeFromPeerInfo(requestingPeerInfo)
	targetNAT := t.parseNATTypeFromPeerInfo(targetPeerInfo)
	
	// Determine who should initiate connection based on NAT levels
	var initiator, responder *ClientConnection
	var initiatorPeerInfo, responderPeerInfo string
	
	if requestingNAT.GetLevel() > targetNAT.GetLevel() {
		// Requesting client has worse NAT, it should initiate
		initiator = requestingClient
		responder = targetClient
		initiatorPeerInfo = targetPeerInfo
		responderPeerInfo = requestingPeerInfo
		log.Printf("NAT-based decision: %s (NAT level %d) will initiate to %s (NAT level %d)",
			requestingIP, requestingNAT.GetLevel(), targetIP, targetNAT.GetLevel())
	} else if requestingNAT.GetLevel() < targetNAT.GetLevel() {
		// Target has worse NAT, it should initiate
		initiator = targetClient
		responder = requestingClient
		initiatorPeerInfo = requestingPeerInfo
		responderPeerInfo = targetPeerInfo
		log.Printf("NAT-based decision: %s (NAT level %d) will initiate to %s (NAT level %d)",
			targetIP, targetNAT.GetLevel(), requestingIP, requestingNAT.GetLevel())
	} else {
		// Same NAT level, requesting client tries first
		initiator = requestingClient
		responder = targetClient
		initiatorPeerInfo = targetPeerInfo
		responderPeerInfo = requestingPeerInfo
		log.Printf("Same NAT level: %s (requester) will try first, then %s if it fails",
			requestingIP, targetIP)
	}
	
	// Send peer info and PUNCH to initiator
	t.sendPeerInfoAndPunch(initiator, initiatorPeerInfo)
	
	// Also send to responder so it's ready to respond
	t.sendPeerInfoAndPunch(responder, responderPeerInfo)
	
	log.Printf("P2P coordination complete for %s <-> %s", requestingIP, targetIP)
}

// parseNATTypeFromPeerInfo extracts NAT type from peer info string
func (t *Tunnel) parseNATTypeFromPeerInfo(peerInfo string) nat.NATType {
	// Format: TunnelIP|PublicAddr|LocalAddr|NATType (NAT type is optional)
	// NATType is sent as an integer (0-5) not as a string
	parts := strings.Split(peerInfo, "|")
	if len(parts) >= 4 {
		// Parse NAT type as integer
		var natTypeNum int
		if _, err := fmt.Sscanf(parts[3], "%d", &natTypeNum); err == nil {
			// Convert integer to NATType enum
			switch natTypeNum {
			case 0:
				return nat.NATUnknown
			case 1:
				return nat.NATNone
			case 2:
				return nat.NATFullCone
			case 3:
				return nat.NATRestrictedCone
			case 4:
				return nat.NATPortRestrictedCone
			case 5:
				return nat.NATSymmetric
			}
		}
	}
	// Default to unknown if not specified or parse fails
	return nat.NATUnknown
}

// sendPeerInfoAndPunch sends peer info and punch request to a client with timing coordination
func (t *Tunnel) sendPeerInfoAndPunch(client *ClientConnection, peerInfo string) {
	// Send peer info
	peerInfoPacket := make([]byte, len(peerInfo)+1)
	peerInfoPacket[0] = PacketTypePeerInfo
	copy(peerInfoPacket[1:], []byte(peerInfo))
	
	encryptedPeerInfo, err := t.encryptForClient(client, peerInfoPacket)
	if err != nil {
		log.Printf("Failed to encrypt peer info: %v", err)
		return
	}
	
	if err := client.conn.WritePacket(encryptedPeerInfo); err != nil {
		log.Printf("Failed to send peer info: %v", err)
		return
	}
	
	// Send PUNCH command with timing hint for symmetric NAT
	// Format: peerInfo|timestamp_ms (timestamp for coordination)
	punchDelay := 200 // milliseconds - delay before starting punch attempts
	punchInfo := fmt.Sprintf("%s|%d", peerInfo, time.Now().UnixMilli()+int64(punchDelay))
	punchPacket := make([]byte, len(punchInfo)+1)
	punchPacket[0] = PacketTypePunch
	copy(punchPacket[1:], []byte(punchInfo))
	
	encryptedPunch, err := t.encryptForClient(client, punchPacket)
	if err != nil {
		log.Printf("Failed to encrypt punch packet: %v", err)
		return
	}
	
	if err := client.conn.WritePacket(encryptedPunch); err != nil {
		log.Printf("Failed to send punch packet: %v", err)
	}
}

// broadcastPeerInfo is no longer used in on-demand P2P mode
// Connections are established only when needed via handleP2PRequest

// routePacket handles the routing of a data packet from a client
func (t *Tunnel) routePacket(client *ClientConnection, payload []byte) {
	// Extract source IP from the packet to register client
	if payload[0]>>4 == IPv4Version { // IPv4
		srcIP := net.IP(payload[IPv4SrcIPOffset : IPv4SrcIPOffset+4])

		// Register client IP if not yet registered
		client.mu.RLock()
		cIP := client.clientIP
		client.mu.RUnlock()

		if cIP == nil {
			// Prevent source IP spoofing: reject if srcIP is server's IP
			if srcIP.Equal(t.myTunnelIP) {
				log.Printf("WARNING: Client %s attempting to spoof source IP as server IP %s. Dropping packet.",
					client.conn.RemoteAddr(), srcIP)
				return
			}

			// Prevent source IP spoofing: reject if srcIP is already registered to another client
			if existingClient := t.getClientByIP(srcIP); existingClient != nil && existingClient != client {
				log.Printf("WARNING: Client %s attempting to use source IP %s already registered to %s. Dropping packet.",
					client.conn.RemoteAddr(), srcIP, existingClient.conn.RemoteAddr())
				return
			}

			// First packet from this client, register its IP
			t.addClient(client, srcIP)
		} else if !cIP.Equal(srcIP) {
			// Client is trying to send packets with a different source IP
			// This is a potential DoS/hijacking attempt or routing loop
			log.Printf("WARNING: Client %s trying to send packet with different source IP %s (registered as %s). Possible IP spoofing or routing loop. Dropping packet.",
				client.conn.RemoteAddr(), srcIP, cIP)
			return
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

				// IMPORTANT: payload comes from aead.Open which allocates a new slice
				// We need to copy it into a pooled buffer so it can be properly recycled
				forwardBuf := t.getPacketBuffer()
				
				// Ensure we don't exceed buffer capacity
				copyLen := len(payload)
				if copyLen > len(forwardBuf) {
					copyLen = len(forwardBuf)
				}
				forwardPacket := forwardBuf[:copyLen]
				copy(forwardPacket, payload)

				queued := false
				select {
				case targetClient.sendQueue <- forwardPacket:
					queued = true
				case <-t.stopCh:
					t.releasePacketBuffer(forwardBuf)
					return
				case <-client.stopCh:
					t.releasePacketBuffer(forwardBuf)
					return
				case <-time.After(QueueSendTimeout):
					// Wait for queue space
					select {
					case targetClient.sendQueue <- forwardPacket:
						queued = true
					case <-t.stopCh:
						t.releasePacketBuffer(forwardBuf)
						return
					case <-client.stopCh:
						t.releasePacketBuffer(forwardBuf)
						return
					default:
						log.Printf("⚠️  Target client send queue full for %s after timeout, dropping packet", dstIP)
						t.releasePacketBuffer(forwardBuf)
					}
				}
				// Only release if not queued (clientNetWriter will release if queued)
				if !queued {
					t.releasePacketBuffer(forwardBuf)
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
}

