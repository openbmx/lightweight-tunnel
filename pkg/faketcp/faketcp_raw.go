package faketcp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openbmx/lightweight-tunnel/pkg/iptables"
	"github.com/openbmx/lightweight-tunnel/pkg/rawsocket"
)

const (
	rawRecvQueueSize = 4096 // large buffer to avoid drops under high throughput
	
	// metricsReportInterval is how often to log packet filtering statistics
	// Helps monitor raw socket filtering efficiency in production
	metricsReportInterval = 60 * time.Second
	
	// maxBufferedPackets limits out-of-order packet buffer size
	// Value chosen based on typical TCP window size and memory constraints:
	// - 32 packets * 1500 bytes/packet = 48KB max memory per connection
	// - Covers reasonable out-of-order scenarios without excessive memory usage
	// - Prevents memory exhaustion from malicious out-of-order packet floods
	maxBufferedPackets = 32
)

// ConnRaw represents a fake TCP connection using raw sockets (真正的TCP伪装)
//
// PERFORMANCE CONSIDERATIONS:
// Raw sockets (IPPROTO_TCP) in Linux receive ALL TCP packets destined for the host.
// In server mode, each client connection shares the same raw socket (via ListenerRaw),
// which is efficient. However, the kernel still delivers ALL packets to each raw socket,
// and filtering happens in user space.
//
// Server mode uses a shared raw socket in ListenerRaw which minimizes overhead.
// Client connections created via DialRaw each get their own raw socket, but this
// is acceptable since clients typically have only one connection.
//
// The recvLoop filters packets by connection tuple (src/dst IP:port) to ensure
// only relevant packets are processed. This filtering is necessary since raw sockets
// don't provide the automatic demultiplexing that normal TCP sockets do.
type ConnRaw struct {
	rawSocket     *rawsocket.RawSocket
	localIP       net.IP
	localPort     uint16
	remoteIP      net.IP
	remotePort    uint16
	srcPort       uint16
	dstPort       uint16
	seqNum        uint32
	ackNum        uint32
	mu            sync.Mutex
	isConnected   bool // true if client connection, false if server listener connection
	recvQueue     chan []byte
	closed        int32
	closeOnce     sync.Once
	iptablesMgr   *iptables.IPTablesManager
	stopCh        chan struct{}
	wg            sync.WaitGroup
	isListener    bool      // true表示这是listener接受的连接，不需要启动recvLoop
	ownsResources bool      // true表示拥有rawSocket和iptablesMgr的所有权，关闭时需要清理
	lastActivity  time.Time // Last time this connection had activity (for cleanup)
	
	// DPI resistance: sliding window and out-of-order handling
	recvWindow     map[uint32][]byte // out-of-order packet buffer (seq -> payload)
	recvWindowMu   sync.Mutex        // protects recvWindow
	expectedSeq    uint32            // next expected sequence number
	windowSize     uint32            // TCP receive window size
}

// NewConnRaw creates a new raw socket connection
func NewConnRaw(localIP net.IP, localPort uint16, remoteIP net.IP, remotePort uint16, isClient bool) (*ConnRaw, error) {
	// Generate random ISN
	isn, err := randomUint32()
	if err != nil {
		return nil, err
	}

	// Create raw socket
	rawSock, err := rawsocket.NewRawSocket(localIP, localPort, remoteIP, remotePort, !isClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create raw socket: %v", err)
	}

	// Create iptables manager and add rules
	iptablesMgr := iptables.NewIPTablesManager()
	if err := iptablesMgr.AddRuleForPort(localPort, !isClient); err != nil {
		rawSock.Close()
		return nil, fmt.Errorf("failed to add iptables rule: %v", err)
	}

	conn := &ConnRaw{
		rawSocket:     rawSock,
		localIP:       localIP,
		localPort:     localPort,
		remoteIP:      remoteIP,
		remotePort:    remotePort,
		srcPort:       localPort,
		dstPort:       remotePort,
		seqNum:        isn,
		ackNum:        0,
		isConnected:   false, // 握手未完成，初始为false
		recvQueue:     make(chan []byte, rawRecvQueueSize),
		iptablesMgr:   iptablesMgr,
		stopCh:        make(chan struct{}),
		isListener:    false,
		ownsResources: true, // 客户端连接拥有资源所有权
		recvWindow:    make(map[uint32][]byte),
		expectedSeq:   0,       // Will be set after handshake
		windowSize:    65535,   // Standard TCP window size
	}

	// 只有客户端连接才启动recvLoop，服务端连接由acceptLoop统一分发
	if isClient {
		conn.wg.Add(1)
		go conn.recvLoop()
	}

	return conn, nil
}

// DialRaw creates a client connection using raw sockets
func DialRaw(remoteAddr string, timeout time.Duration) (*ConnRaw, error) {
	// Parse remote address
	host, portStr, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %v", err)
	}

	remoteIP := net.ParseIP(host)
	if remoteIP == nil {
		// Resolve hostname
		ips, err := net.LookupIP(host)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve hostname: %v", err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no IP addresses found for hostname")
		}
		remoteIP = ips[0]
	}
	remoteIP = remoteIP.To4()
	if remoteIP == nil {
		return nil, fmt.Errorf("only IPv4 is supported")
	}

	var remotePort uint16
	fmt.Sscanf(portStr, "%d", &remotePort)

	// Get local IP by creating a temporary connection
	tempConn, err := net.Dial("udp", remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to determine local IP: %v", err)
	}
	localIP := tempConn.LocalAddr().(*net.UDPAddr).IP.To4()
	tempConn.Close()

	// Use a random local port
	localPort := uint16(20000 + (randomUint32Value() % 40000))

	// Create connection
	conn, err := NewConnRaw(localIP, localPort, remoteIP, remotePort, true)
	if err != nil {
		return nil, err
	}

	// Perform TCP handshake
	if err := conn.performHandshake(timeout); err != nil {
		conn.Close()
		return nil, fmt.Errorf("handshake failed: %v", err)
	}

	log.Printf("Raw TCP connection established: %s:%d -> %s:%d", localIP, localPort, remoteIP, remotePort)
	return conn, nil
}

// performHandshake performs TCP three-way handshake
func (c *ConnRaw) performHandshake(timeout time.Duration) error {
	// Build TCP options
	tcpOptions := c.buildTCPOptions()

	// Retry mechanism for SYN
	maxRetries := 3
	retryInterval := 500 * time.Millisecond

	for retry := 0; retry < maxRetries; retry++ {
		if retry > 0 {
			time.Sleep(retryInterval)
		}

		// Send SYN
		err := c.rawSocket.SendPacket(c.localIP, c.localPort, c.remoteIP, c.remotePort,
			c.seqNum, 0, SYN, tcpOptions, nil)
		if err != nil {
			continue
		}

		// Wait for SYN-ACK with timeout
		deadline := time.Now().Add(timeout / time.Duration(maxRetries))
		for time.Now().Before(deadline) {
			select {
			case data := <-c.recvQueue:
				// Parse TCP header from data
				if len(data) < TCPHeaderSize {
					continue
				}
				hdr := parseTCPHeader(data)
				if hdr == nil {
					continue
				}
				if hdr.Flags&(SYN|ACK) == (SYN | ACK) {
					// Got SYN-ACK
					c.seqNum++ // SYN consumes one sequence number
					c.ackNum = hdr.SeqNum + 1
					
					// Initialize expected sequence for DPI resistance
					c.recvWindowMu.Lock()
					c.expectedSeq = c.ackNum
					c.recvWindowMu.Unlock()

					// Send ACK
					err = c.rawSocket.SendPacket(c.localIP, c.localPort, c.remoteIP, c.remotePort,
						c.seqNum, c.ackNum, ACK, tcpOptions, nil)
					if err != nil {
						return fmt.Errorf("failed to send ACK: %v", err)
					}
					// 握手成功，标记为已连接
					c.mu.Lock()
					c.isConnected = true
					c.mu.Unlock()

					// 清空recvQueue中的握手包（可能有重传的SYN-ACK等）
					for {
						select {
						case <-c.recvQueue:
							// 丢弃握手期间积压的包
						default:
							// 队列已空，返回
							return nil
						}
					}
				}
			case <-time.After(200 * time.Millisecond):
				// Continue waiting
			}
		}
	}

	return fmt.Errorf("handshake timeout after %d retries", maxRetries)
}

// recvLoop continuously receives packets from raw socket (只用于客户端连接)
// PERFORMANCE NOTE: Raw sockets receive ALL TCP packets destined for the host.
// Current implementation filters packets in user space by checking connection tuple.
// Future optimization: Consider using BPF (Berkeley Packet Filter) for kernel-space
// filtering to reduce CPU usage in high-traffic environments.
func (c *ConnRaw) recvLoop() {
	defer c.wg.Done()

	// 如果是listener接受的连接，不应该运行recvLoop
	if c.isListener {
		return
	}
	
	// Metrics for monitoring filtering efficiency
	var totalPacketsReceived uint64
	var packetsFiltered uint64
	var packetsProcessed uint64
	metricsInterval := time.NewTicker(metricsReportInterval)
	defer metricsInterval.Stop()

	buf := make([]byte, 65535)
	for {
		select {
		case <-c.stopCh:
			return
		case <-metricsInterval.C:
			// Log filtering efficiency metrics periodically
			if totalPacketsReceived > 0 {
				filterRate := float64(packetsFiltered) / float64(totalPacketsReceived) * 100
				log.Printf("Raw socket filtering efficiency: %d total, %d filtered (%.1f%%), %d processed",
					totalPacketsReceived, packetsFiltered, filterRate, packetsProcessed)
			}
			// Reset counters
			totalPacketsReceived = 0
			packetsFiltered = 0
			packetsProcessed = 0
		default:
		}

		// Set read timeout to allow checking stopCh
		c.rawSocket.SetReadTimeout(0, 100000) // 100ms = 100000 microseconds

		srcIP, srcPort, dstIP, dstPort, seq, ack, flags, payload, err := c.rawSocket.RecvPacket(buf)
		if err != nil {
			// Timeout or other errors - continue
			continue
		}
		
		totalPacketsReceived++

		// Filter packets: only accept packets for our connection
		// This is necessary because raw sockets don't provide automatic demultiplexing
		if c.isConnected {
			// Client mode: accept packets from server
			if !srcIP.Equal(c.remoteIP) || srcPort != c.remotePort {
				packetsFiltered++
				continue
			}
			if !dstIP.Equal(c.localIP) || dstPort != c.localPort {
				packetsFiltered++
				continue
			}
		} else {
			// Server mode: accept packets from any client (will be handled by listener)
			if !dstIP.Equal(c.localIP) || dstPort != c.localPort {
				packetsFiltered++
				continue
			}
		}
		
		packetsProcessed++

		// Update ack number and immediately acknowledge payload to keep TCP disguise realistic
		if len(payload) > 0 {
			c.mu.Lock()
			c.ackNum = seq + uint32(len(payload))
			ackToSend := c.ackNum
			seqToUse := c.seqNum
			c.mu.Unlock()

			if c.isConnected {
				if err := c.rawSocket.SendPacket(c.localIP, c.srcPort, c.remoteIP, c.dstPort,
					seqToUse, ackToSend, ACK, c.buildTCPOptions(), nil); err != nil {
					log.Printf("Failed to send ACK to %s:%d: %v", c.remoteIP, c.remotePort, err)
				}
			}
		}

		// 只在已连接状态下过滤payload=0的包
		// 握手期间（!isConnected）需要处理SYN-ACK等控制包
		if c.isConnected && len(payload) == 0 {
			continue
		}

		// Build packet data including TCP header for compatibility
		// Format: TCP header + payload
		tcpHdr := &TCPHeader{
			SrcPort:    srcPort,
			DstPort:    dstPort,
			SeqNum:     seq,
			AckNum:     ack,
			DataOffset: 5,
			Flags:      flags,
			Window:     65535,
		}

		headerBytes := serializeTCPHeaderStatic(tcpHdr)
		fullData := make([]byte, len(headerBytes)+len(payload))
		copy(fullData, headerBytes)
		copy(fullData[len(headerBytes):], payload)

		// Queue received data
		if atomic.LoadInt32(&c.closed) == 0 {
			select {
			case c.recvQueue <- fullData:
			default:
				// Queue full, drop packet
			}
		}
	}
}

// WritePacket sends data with fake TCP header (API compatibility)
func (c *ConnRaw) WritePacket(data []byte) error {
	if atomic.LoadInt32(&c.closed) != 0 {
		return fmt.Errorf("connection closed")
	}

	// Segment data into smaller chunks if needed
	const maxSegment = 1400

	// Log warning if data will be segmented (indicates potential encryption issue)
	if len(data) > maxSegment {
		log.Printf("⚠️  WARNING: Packet size %d exceeds maxSegment %d, will be segmented into %d parts. "+
			"This may cause decryption errors if data is encrypted. "+
			"MTU should have been auto-adjusted to %d when encryption is enabled. "+
			"Check if MTU was manually set too high or if auto-adjustment was bypassed.",
			len(data), maxSegment, (len(data)+maxSegment-1)/maxSegment, maxSegment-29) // 29 = 1 packet type + 28 encryption overhead
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for offset := 0; offset < len(data); offset += maxSegment {
		end := offset + maxSegment
		if end > len(data) {
			end = len(data)
		}
		segment := data[offset:end]

		tcpOptions := c.buildTCPOptions()
		err := c.rawSocket.SendPacket(c.localIP, c.srcPort, c.remoteIP, c.dstPort,
			c.seqNum, c.ackNum, PSH|ACK, tcpOptions, segment)
		if err != nil {
			return fmt.Errorf("failed to send packet: %v", err)
		}

		c.seqNum += uint32(len(segment))
	}

	return nil
}

// ReadPacket receives data (API compatibility)
func (c *ConnRaw) ReadPacket() ([]byte, error) {
	if !c.isConnected {
		// Listener connection - read from queue
		select {
		case data, ok := <-c.recvQueue:
			if !ok {
				return nil, fmt.Errorf("connection closed")
			}
			// Extract payload (skip TCP header)
			if len(data) < TCPHeaderSize {
				return nil, fmt.Errorf("invalid packet")
			}
			hdr := parseTCPHeader(data)
			if hdr == nil {
				return nil, fmt.Errorf("failed to parse TCP header")
			}
			headerLen := int(hdr.DataOffset) * 4
			if headerLen < TCPHeaderSize {
				headerLen = TCPHeaderSize
			}
			if len(data) <= headerLen {
				// No payload, return empty
				return []byte{}, nil
			}
			return data[headerLen:], nil
		case <-time.After(ListenerReadTimeout):
			if atomic.LoadInt32(&c.closed) != 0 {
				return nil, fmt.Errorf("connection closed")
			}
			return nil, &net.OpError{Op: "read", Net: "tcp", Err: fmt.Errorf("timeout")}
		}
	}

	// Connected socket - read from queue
	select {
	case data, ok := <-c.recvQueue:
		if !ok {
			return nil, fmt.Errorf("connection closed")
		}
		// Extract payload
		if len(data) < TCPHeaderSize {
			return nil, fmt.Errorf("invalid packet")
		}
		hdr := parseTCPHeader(data)
		if hdr == nil {
			return nil, fmt.Errorf("failed to parse TCP header")
		}
		headerLen := int(hdr.DataOffset) * 4
		if headerLen < TCPHeaderSize {
			headerLen = TCPHeaderSize
		}
		if len(data) <= headerLen {
			return []byte{}, nil
		}
		return data[headerLen:], nil
	case <-time.After(30 * time.Second): // 30秒超时，适合隧道长连接
		return nil, &net.OpError{Op: "read", Net: "tcp", Err: fmt.Errorf("timeout")}
	}
}

// buildTCPOptions builds TCP options
func (c *ConnRaw) buildTCPOptions() []byte {
	opts := make([]byte, 0)

	// MSS
	mssOpt := make([]byte, 4)
	mssOpt[0] = 2
	mssOpt[1] = 4
	binary.BigEndian.PutUint16(mssOpt[2:], 1460)
	opts = append(opts, mssOpt...)

	// NOP
	opts = append(opts, 1)

	// Window scale
	opts = append(opts, 3, 3, 7)

	// SACK permitted
	opts = append(opts, 4, 2)

	// Timestamp
	tsOpt := make([]byte, 10)
	tsOpt[0] = 8
	tsOpt[1] = 10
	binary.BigEndian.PutUint32(tsOpt[2:], uint32(time.Now().Unix()))
	binary.BigEndian.PutUint32(tsOpt[6:], 0)
	opts = append(opts, 1) // NOP before TS
	opts = append(opts, tsOpt...)

	return opts
}

// Close closes the connection
func (c *ConnRaw) Close() error {
	if !atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		return nil
	}

	// Send FIN
	c.mu.Lock()
	tcpOptions := c.buildTCPOptions()
	c.rawSocket.SendPacket(c.localIP, c.srcPort, c.remoteIP, c.dstPort,
		c.seqNum, c.ackNum, FIN|ACK, tcpOptions, nil)
	c.mu.Unlock()

	// Stop receive loop
	close(c.stopCh)
	c.wg.Wait()

	// 只有拥有资源的连接才关闭socket和删除iptables规则
	if c.ownsResources {
		// Close raw socket
		if err := c.rawSocket.Close(); err != nil {
			log.Printf("Error closing raw socket: %v", err)
		}

		// Remove iptables rules
		if err := c.iptablesMgr.RemoveAllRules(); err != nil {
			log.Printf("Error removing iptables rules: %v", err)
		}
	}

	// Close receive queue
	c.closeOnce.Do(func() {
		close(c.recvQueue)
	})

	return nil
}

// LocalAddr returns local address
func (c *ConnRaw) LocalAddr() net.Addr {
	return &net.TCPAddr{
		IP:   c.localIP,
		Port: int(c.localPort),
	}
}

// RemoteAddr returns remote address
func (c *ConnRaw) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP:   c.remoteIP,
		Port: int(c.remotePort),
	}
}

// SetDeadline sets read and write deadlines (no-op for raw sockets)
func (c *ConnRaw) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline sets read deadline (no-op for raw sockets)
func (c *ConnRaw) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline sets write deadline (no-op for raw sockets)
func (c *ConnRaw) SetWriteDeadline(t time.Time) error {
	return nil
}

// Helper function to get a random uint32 value
func randomUint32Value() uint32 {
	n, _ := rand.Int(rand.Reader, big.NewInt(0x100000000))
	return uint32(n.Int64())
}

// ListenerRaw listens for raw socket connections
type ListenerRaw struct {
	rawSocket   *rawsocket.RawSocket
	localIP     net.IP
	localPort   uint16
	connMap     map[string]*ConnRaw
	mu          sync.RWMutex
	iptablesMgr *iptables.IPTablesManager
	acceptQueue chan *ConnRaw
	stopCh      chan struct{}
	wg          sync.WaitGroup
}

const (
	// staleConnectionTimeout defines how long a connection can be idle before being cleaned up
	staleConnectionTimeout = 60 * time.Second
	// cleanupInterval defines how often to run the connection cleanup
	cleanupInterval = 30 * time.Second
	// shutdownTimeout is the maximum time to wait for goroutines during listener shutdown
	shutdownTimeout = 3 * time.Second
)

// ListenRaw creates a raw socket listener
func ListenRaw(addr string) (*ListenerRaw, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %v", err)
	}

	var localIP net.IP
	if host == "" || host == "0.0.0.0" {
		localIP = net.IPv4zero
	} else {
		localIP = net.ParseIP(host)
		if localIP == nil {
			return nil, fmt.Errorf("invalid IP address")
		}
		localIP = localIP.To4()
	}

	var localPort uint16
	fmt.Sscanf(portStr, "%d", &localPort)

	// Create raw socket
	rawSock, err := rawsocket.NewRawSocket(localIP, localPort, nil, 0, true)
	if err != nil {
		return nil, fmt.Errorf("failed to create raw socket: %v", err)
	}

	// Create iptables manager and add rules
	iptablesMgr := iptables.NewIPTablesManager()
	if err := iptablesMgr.AddRuleForPort(localPort, true); err != nil {
		rawSock.Close()
		return nil, fmt.Errorf("failed to add iptables rule: %v", err)
	}

	listener := &ListenerRaw{
		rawSocket:   rawSock,
		localIP:     localIP,
		localPort:   localPort,
		connMap:     make(map[string]*ConnRaw),
		iptablesMgr: iptablesMgr,
		acceptQueue: make(chan *ConnRaw, 10),
		stopCh:      make(chan struct{}),
	}

	// Start accept loop
	listener.wg.Add(1)
	go listener.acceptLoop()

	// Start cleanup loop for stale connections
	listener.wg.Add(1)
	go listener.cleanupLoop()

	log.Printf("Raw TCP listener started on %s:%d", localIP, localPort)
	return listener, nil
}

// acceptLoop handles incoming connections
func (l *ListenerRaw) acceptLoop() {
	defer l.wg.Done()
	
	// Metrics for monitoring server-side filtering efficiency
	var totalPacketsReceived uint64
	var packetsFiltered uint64
	var packetsProcessed uint64
	metricsInterval := time.NewTicker(metricsReportInterval)
	defer metricsInterval.Stop()

	buf := make([]byte, 65535)
	for {
		select {
		case <-l.stopCh:
			return
		case <-metricsInterval.C:
			// Log filtering efficiency metrics periodically
			if totalPacketsReceived > 0 {
				filterRate := float64(packetsFiltered) / float64(totalPacketsReceived) * 100
				log.Printf("Server raw socket filtering: %d total, %d filtered (%.1f%%), %d processed",
					totalPacketsReceived, packetsFiltered, filterRate, packetsProcessed)
			}
			// Reset counters
			totalPacketsReceived = 0
			packetsFiltered = 0
			packetsProcessed = 0
		default:
		}

		l.rawSocket.SetReadTimeout(0, 100000) // 100ms
		srcIP, srcPort, dstIP, dstPort, seq, ack, flags, payload, err := l.rawSocket.RecvPacket(buf)
		if err != nil {
			continue
		}
		
		totalPacketsReceived++

		// Filter packets for our port
		// PERFORMANCE: This is basic port-based filtering in user space
		// For production with high traffic, consider BPF for kernel-space filtering
		if dstPort != l.localPort {
			packetsFiltered++
			continue
		}
		
		packetsProcessed++

		connKey := fmt.Sprintf("%s:%d", srcIP.String(), srcPort)

		l.mu.Lock()
		conn, exists := l.connMap[connKey]

		// Remove stale closed connection entries to allow reconnection from the same peer
		if exists && atomic.LoadInt32(&conn.closed) != 0 {
			delete(l.connMap, connKey)
			conn = nil
			exists = false
		}

		// 1. 处理新连接的SYN
		if !exists && (flags&SYN != 0) && (flags&ACK == 0) {
			isn, _ := randomUint32()

			newConn := &ConnRaw{
				rawSocket:     l.rawSocket,
				localIP:       dstIP,
				localPort:     dstPort,
				remoteIP:      srcIP,
				remotePort:    srcPort,
				srcPort:       dstPort,
				dstPort:       srcPort,
				seqNum:        isn,
				ackNum:        seq + 1,
				isConnected:   false,
				recvQueue:     make(chan []byte, rawRecvQueueSize),
				iptablesMgr:   l.iptablesMgr,
				stopCh:        make(chan struct{}),
				isListener:    true,
				ownsResources: false,        // 服务端连接不拥有资源（共享）
				lastActivity:  time.Now(),   // Initialize lastActivity
				recvWindow:    make(map[uint32][]byte),
				expectedSeq:   seq + 1,      // Expect next byte after SYN
				windowSize:    65535,        // Standard TCP window size
			}

			// Send SYN-ACK
			tcpOptions := newConn.buildTCPOptions()
			err := l.rawSocket.SendPacket(dstIP, dstPort, srcIP, srcPort,
				newConn.seqNum, newConn.ackNum, SYN|ACK, tcpOptions, nil)
			if err != nil {
				l.mu.Unlock()
				continue
			}

			newConn.seqNum++ // SYN consumes sequence number
			l.connMap[connKey] = newConn
			l.mu.Unlock()
			continue
		}

		// 2. 处理握手的ACK（第三次握手）
		if exists && !conn.isConnected && (flags&ACK != 0) && (flags&SYN == 0) {
			conn.isConnected = true
			conn.mu.Lock()
			conn.ackNum = seq + uint32(len(payload))
			conn.lastActivity = time.Now()
			conn.mu.Unlock()
			l.mu.Unlock()

			// 放入acceptQueue（非阻塞方式）
			go func(c *ConnRaw) {
				select {
				case l.acceptQueue <- c:
				case <-time.After(2 * time.Second):
					l.mu.Lock()
					delete(l.connMap, connKey)
					l.mu.Unlock()
				}
			}(conn)

			// 如果ACK带了数据，也要处理
			if len(payload) > 0 {
				tcpHdr := &TCPHeader{
					SrcPort:    srcPort,
					DstPort:    dstPort,
					SeqNum:     seq,
					AckNum:     ack,
					DataOffset: 5,
					Flags:      flags,
					Window:     65535,
				}
				headerBytes := serializeTCPHeaderStatic(tcpHdr)
				fullData := make([]byte, len(headerBytes)+len(payload))
				copy(fullData, headerBytes)
				copy(fullData[len(headerBytes):], payload)

				select {
				case conn.recvQueue <- fullData:
				default:
				}
			}
			continue
		}

		// 3. 处理已连接的数据包
		if exists && conn.isConnected {
			// Update last activity time for all packets (including control packets)
			conn.mu.Lock()
			conn.lastActivity = time.Now()
			conn.mu.Unlock()

			// Handle FIN or RST packets (connection close)
			if flags&(FIN|RST) != 0 {
				// Connection is being closed
				log.Printf("Received %s from %s:%d, closing connection",
					func() string {
						if flags&FIN != 0 {
							return "FIN"
						}
						return "RST"
					}(), srcIP, srcPort)
				
				// Mark connection as closed
				atomic.StoreInt32(&conn.closed, 1)
				
				// Send ACK for FIN if needed
				if flags&FIN != 0 {
					conn.mu.Lock()
					conn.ackNum = seq + 1 // FIN consumes one sequence number
					ackToSend := conn.ackNum
					seqToUse := conn.seqNum
					conn.mu.Unlock()
					
					if err := l.rawSocket.SendPacket(conn.localIP, conn.srcPort, conn.remoteIP, conn.dstPort,
						seqToUse, ackToSend, ACK, conn.buildTCPOptions(), nil); err != nil {
						log.Printf("Failed to send ACK for FIN to %s:%d: %v", conn.remoteIP, conn.remotePort, err)
					}
				}
				
				// Remove from connection map
				delete(l.connMap, connKey)
				l.mu.Unlock()
				continue
			}

			// 只处理有实际数据的包，忽略纯ACK、keepalive等控制包
			if len(payload) > 0 {
				conn.mu.Lock()
				conn.ackNum = seq + uint32(len(payload))
				conn.lastActivity = time.Now()
				ackToSend := conn.ackNum
				seqToUse := conn.seqNum
				conn.mu.Unlock()

				// 立即回 ACK，避免长时间无反向流量导致被误判为异常
				if err := l.rawSocket.SendPacket(conn.localIP, conn.srcPort, conn.remoteIP, conn.dstPort,
					seqToUse, ackToSend, ACK, conn.buildTCPOptions(), nil); err != nil {
					log.Printf("Failed to send ACK to %s:%d: %v", conn.remoteIP, conn.remotePort, err)
				}

				tcpHdr := &TCPHeader{
					SrcPort:    srcPort,
					DstPort:    dstPort,
					SeqNum:     seq,
					AckNum:     ack,
					DataOffset: 5,
					Flags:      flags,
					Window:     65535,
				}

				headerBytes := serializeTCPHeaderStatic(tcpHdr)
				fullData := make([]byte, len(headerBytes)+len(payload))
				copy(fullData, headerBytes)
				copy(fullData[len(headerBytes):], payload)

				select {
				case conn.recvQueue <- fullData:
				default:
					// 队列满，丢弃
				}
			}
			// FIN/RST包不需要放入queue，连接关闭会由其他机制处理
			l.mu.Unlock()
			continue
		}

		// 其他情况：未知连接或无效状态的包，直接忽略
		l.mu.Unlock()
	}
}

// Accept accepts a new connection
func (l *ListenerRaw) Accept() (*ConnRaw, error) {
	select {
	case conn := <-l.acceptQueue:
		// 清空握手期间积压的控制包
		for {
			select {
			case <-conn.recvQueue:
				// 丢弃
			default:
				return conn, nil
			}
		}
	case <-l.stopCh:
		return nil, fmt.Errorf("listener closed")
	}
}

// cleanupLoop periodically removes stale connections from connMap
func (l *ListenerRaw) cleanupLoop() {
	defer l.wg.Done()

	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-l.stopCh:
			return
		case <-ticker.C:
			l.cleanupStaleConnections()
		}
	}
}

// cleanupStaleConnections removes connections that are closed or have been idle too long
func (l *ListenerRaw) cleanupStaleConnections() {
	now := time.Now()
	staleKeys := make([]string, 0)

	// First pass: find stale connections (with read lock)
	l.mu.RLock()
	for key, conn := range l.connMap {
		// Mark closed connections for removal
		if atomic.LoadInt32(&conn.closed) != 0 {
			staleKeys = append(staleKeys, key)
			continue
		}

		// Mark idle connections for removal
		conn.mu.Lock()
		lastActivity := conn.lastActivity
		conn.mu.Unlock()

		if !lastActivity.IsZero() && now.Sub(lastActivity) > staleConnectionTimeout {
			staleKeys = append(staleKeys, key)
		}
	}
	l.mu.RUnlock()

	// Second pass: remove stale connections (with write lock)
	if len(staleKeys) > 0 {
		l.mu.Lock()
		for _, key := range staleKeys {
			if conn, exists := l.connMap[key]; exists {
				// Double-check the connection is still stale
				if atomic.LoadInt32(&conn.closed) != 0 {
					delete(l.connMap, key)
					continue
				}
				conn.mu.Lock()
				lastActivity := conn.lastActivity
				conn.mu.Unlock()
				if !lastActivity.IsZero() && now.Sub(lastActivity) > staleConnectionTimeout {
					// Close the stale connection
					atomic.StoreInt32(&conn.closed, 1)
					delete(l.connMap, key)
					log.Printf("Cleaned up stale connection from %s (idle for %v)", key, now.Sub(lastActivity))
				}
			}
		}
		l.mu.Unlock()
	}
}

// Close closes the listener
func (l *ListenerRaw) Close() error {
	close(l.stopCh)

	// Wait for goroutines with timeout to avoid hang
	done := make(chan struct{})
	go func() {
		l.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All goroutines finished cleanly
	case <-time.After(shutdownTimeout):
		log.Printf("Timeout waiting for listener goroutines to stop; continuing shutdown")
	}

	// Remove iptables rules
	if err := l.iptablesMgr.RemoveAllRules(); err != nil {
		log.Printf("Error removing iptables rules: %v", err)
	}

	// Close raw socket
	return l.rawSocket.Close()
}

// Addr returns the listener's address
func (l *ListenerRaw) Addr() net.Addr {
	return &net.TCPAddr{
		IP:   l.localIP,
		Port: int(l.localPort),
	}
}

// handleOutOfOrderPacket buffers out-of-order packets and returns ordered payloads when gaps are filled
// This makes the TCP stream more realistic for DPI inspection
func (c *ConnRaw) handleOutOfOrderPacket(seq uint32, payload []byte) [][]byte {
	c.recvWindowMu.Lock()
	defer c.recvWindowMu.Unlock()
	
	// Fast path: packet is in order
	if seq == c.expectedSeq {
		result := make([][]byte, 0, 1)
		result = append(result, payload)
		c.expectedSeq += uint32(len(payload))
		
		// Check if we can deliver buffered packets
		for {
			if buffered, exists := c.recvWindow[c.expectedSeq]; exists {
				result = append(result, buffered)
				delete(c.recvWindow, c.expectedSeq)
				c.expectedSeq += uint32(len(buffered))
			} else {
				break
			}
		}
		
		return result
	}
	
	// Out of order packet - buffer it if within window
	// Prevent memory exhaustion from too many buffered packets
	if len(c.recvWindow) < maxBufferedPackets {
		// Only buffer future packets (not duplicates or old packets)
		if seq > c.expectedSeq && seq < c.expectedSeq+c.windowSize {
			c.recvWindow[seq] = payload
		}
	}
	
	// Return empty slice - packet was buffered
	return nil
}
