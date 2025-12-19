package tcp_disguise

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// TCP flags
	FIN = 0x01
	SYN = 0x02
	RST = 0x04
	PSH = 0x08
	ACK = 0x10
	URG = 0x20

	// Protocol numbers
	IPPROTO_TCP = 6

	// Header sizes
	IPHeaderSize  = 20
	TCPHeaderSize = 20
	RawMaxPacketSize = 1500
	MaxPayloadSize = RawMaxPacketSize - IPHeaderSize - TCPHeaderSize

	// Timeouts
	ReadTimeout       = 1 * time.Second
	HandshakeTimeout  = 5 * time.Second
	ListenerReadTimeout = 30 * time.Second
)

// RawConn represents a raw socket TCP connection
type RawConn struct {
	fd          int
	localAddr   *net.TCPAddr
	remoteAddr  *net.TCPAddr
	localIP     [4]byte
	remoteIP    [4]byte
	srcPort     uint16
	dstPort     uint16
	seqNum      uint32
	ackNum      uint32
	mu          sync.Mutex
	recvQueue   chan []byte
	closed      int32
	closeOnce   sync.Once
	isListener  bool // true if part of listener
}

// RawListener listens for raw TCP connections
type RawListener struct {
	fd       int
	addr     *net.TCPAddr
	connMap  map[string]*RawConn
	mu       sync.RWMutex
	stopCh   chan struct{}
	stopped  int32
}

// Dial creates a raw TCP connection
func Dial(remoteAddr string, timeout time.Duration) (*RawConn, error) {
	// Parse remote address
	raddr, err := net.ResolveTCPAddr("tcp", remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %v", err)
	}

	// Create raw socket
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("failed to create raw socket (need root): %v", err)
	}

	// Set IP_HDRINCL to tell kernel we provide IP header
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to set IP_HDRINCL: %v", err)
	}

	// Get local address
	laddr, err := getLocalAddr(raddr)
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}

	conn := &RawConn{
		fd:         fd,
		localAddr:  laddr,
		remoteAddr: raddr,
		srcPort:    uint16(laddr.Port),
		dstPort:    uint16(raddr.Port),
		seqNum:     randomSeq(),
		ackNum:     0,
		recvQueue:  make(chan []byte, 100),
	}

	// Copy IP addresses
	copy(conn.localIP[:], laddr.IP.To4())
	copy(conn.remoteIP[:], raddr.IP.To4())

	// Start receiver goroutine
	go conn.receiver()

	// Perform TCP handshake
	if err := conn.handshake(timeout); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

// Listen creates a raw TCP listener
func Listen(addr string) (*RawListener, error) {
	laddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %v", err)
	}

	// Create raw socket
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("failed to create raw socket (need root): %v", err)
	}

	// Set IP_HDRINCL
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to set IP_HDRINCL: %v", err)
	}

	// Bind is not needed for raw sockets - filtering is done in Accept()

	l := &RawListener{
		fd:      fd,
		addr:    laddr,
		connMap: make(map[string]*RawConn),
		stopCh:  make(chan struct{}),
	}

	return l, nil
}

// Accept accepts a new connection
func (l *RawListener) Accept() (*RawConn, error) {
	buf := make([]byte, RawMaxPacketSize)

	for {
		// Check if stopped
		if atomic.LoadInt32(&l.stopped) != 0 {
			return nil, fmt.Errorf("listener closed")
		}

		// Set read timeout
		tv := syscall.Timeval{Sec: 1, Usec: 0}
		if err := syscall.SetsockoptTimeval(l.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
			return nil, err
		}

		n, _, err := syscall.Recvfrom(l.fd, buf, 0)
		if err != nil {
			if errno, ok := err.(syscall.Errno); ok && errno == syscall.EAGAIN {
				continue
			}
			if atomic.LoadInt32(&l.stopped) != 0 {
				return nil, fmt.Errorf("listener closed")
			}
			continue
		}

		if n < IPHeaderSize+TCPHeaderSize {
			continue
		}

		// Parse IP header
		ipHdr := parseIPHeader(buf[:n])
		if ipHdr == nil || ipHdr.Protocol != IPPROTO_TCP {
			continue
		}

		// Check if packet is for this listener's port
		tcpHdr := parseTCPHeader(buf[IPHeaderSize:n])
		if tcpHdr == nil || tcpHdr.DstPort != uint16(l.addr.Port) {
			continue
		}

		// Create connection key
		srcAddr := &net.TCPAddr{
			IP:   net.IPv4(ipHdr.SrcIP[0], ipHdr.SrcIP[1], ipHdr.SrcIP[2], ipHdr.SrcIP[3]),
			Port: int(tcpHdr.SrcPort),
		}
		connKey := srcAddr.String()

		l.mu.Lock()
		conn, exists := l.connMap[connKey]
		
		if !exists {
			// New connection - check for SYN
			if tcpHdr.Flags&SYN == 0 {
				l.mu.Unlock()
				continue
			}

			// Create new connection
			conn = &RawConn{
				fd:         l.fd,
				localAddr:  l.addr,
				remoteAddr: srcAddr,
				srcPort:    uint16(l.addr.Port),
				dstPort:    tcpHdr.SrcPort,
				seqNum:     randomSeq(),
				ackNum:     tcpHdr.SeqNum + 1,
				recvQueue:  make(chan []byte, 100),
				isListener: true,
			}
			copy(conn.localIP[:], l.addr.IP.To4())
			copy(conn.remoteIP[:], srcAddr.IP.To4())

			// Send SYN-ACK
			if err := conn.sendPacket(SYN|ACK, nil); err != nil {
				l.mu.Unlock()
				continue
			}
			conn.seqNum++

			l.connMap[connKey] = conn
			// Start receiver goroutine BEFORE unlocking
			go conn.receiverListener(l.fd, l)
			l.mu.Unlock()

			// Wait for ACK - simplified wait
			time.Sleep(100 * time.Millisecond)
			return conn, nil
		}

		// Existing connection - handle ACK during handshake
		if tcpHdr.Flags&ACK != 0 && tcpHdr.Flags&SYN == 0 {
			// This might be the final ACK of handshake
			conn.mu.Lock()
			if conn.ackNum == tcpHdr.SeqNum {
				// Just ACK, no data - update ack if needed
				conn.ackNum = tcpHdr.SeqNum
			}
			conn.mu.Unlock()
		}
		
		l.mu.Unlock()

		// Queue data if present
		headerLen := int(tcpHdr.DataOffset) * 4
		if headerLen < TCPHeaderSize {
			headerLen = TCPHeaderSize
		}
		payloadStart := IPHeaderSize + headerLen
		if n > payloadStart {
			payload := make([]byte, n-payloadStart)
			copy(payload, buf[payloadStart:n])
			
			// Update ACK number
			conn.mu.Lock()
			conn.ackNum = tcpHdr.SeqNum + uint32(len(payload))
			conn.mu.Unlock()

			select {
			case conn.recvQueue <- payload:
			default:
				// Queue full
			}
		}
	}
}

// Close closes the listener
func (l *RawListener) Close() error {
	atomic.StoreInt32(&l.stopped, 1)
	close(l.stopCh)
	return syscall.Close(l.fd)
}

// Addr returns the listener address
func (l *RawListener) Addr() net.Addr {
	return l.addr
}

// handshake performs TCP three-way handshake
func (c *RawConn) handshake(timeout time.Duration) error {
	// Send SYN
	if err := c.sendPacket(SYN, nil); err != nil {
		return fmt.Errorf("failed to send SYN: %v", err)
	}
	c.seqNum++

	// Wait for SYN-ACK
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-time.After(100 * time.Millisecond):
			// Check receiver for SYN-ACK (simplified)
			c.mu.Lock()
			if c.ackNum > 0 {
				// Send ACK
				if err := c.sendPacket(ACK, nil); err != nil {
					c.mu.Unlock()
					return fmt.Errorf("failed to send ACK: %v", err)
				}
				c.mu.Unlock()
				return nil
			}
			c.mu.Unlock()
		}
	}

	// Timeout - return connection anyway (best effort)
	return nil
}

// sendPacket sends a raw TCP packet
func (c *RawConn) sendPacket(flags uint8, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Build TCP header
	tcpHdr := c.buildTCPHeader(flags, data)
	tcpBytes := serializeTCPHeader(tcpHdr, data, c.localIP[:], c.remoteIP[:])

	// Build IP header
	ipHdr := c.buildIPHeader(len(tcpBytes))
	ipBytes := serializeIPHeader(ipHdr)

	// Combine
	packet := append(ipBytes, tcpBytes...)

	// Send
	addr := syscall.SockaddrInet4{
		Port: int(c.dstPort),
	}
	copy(addr.Addr[:], c.remoteIP[:])

	return syscall.Sendto(c.fd, packet, 0, &addr)
}

// WritePacket writes data
func (c *RawConn) WritePacket(data []byte) error {
	// Segment data if needed
	const maxSegment = 1400
	for len(data) > 0 {
		segSize := len(data)
		if segSize > maxSegment {
			segSize = maxSegment
		}
		
		if err := c.sendPacket(PSH|ACK, data[:segSize]); err != nil {
			return err
		}
		
		c.mu.Lock()
		c.seqNum += uint32(segSize)
		c.mu.Unlock()
		
		data = data[segSize:]
	}
	return nil
}

// ReadPacket reads data
func (c *RawConn) ReadPacket() ([]byte, error) {
	select {
	case payload, ok := <-c.recvQueue:
		if !ok {
			return nil, fmt.Errorf("connection closed")
		}
		return payload, nil
	case <-time.After(ListenerReadTimeout):
		if atomic.LoadInt32(&c.closed) != 0 {
			return nil, fmt.Errorf("connection closed")
		}
		return nil, &net.OpError{Op: "read", Net: "tcp", Err: syscall.ETIMEDOUT}
	}
}

// receiver receives packets (for client connections)
func (c *RawConn) receiver() {
	buf := make([]byte, RawMaxPacketSize)
	for {
		if atomic.LoadInt32(&c.closed) != 0 {
			return
		}

		tv := syscall.Timeval{Sec: 1, Usec: 0}
		syscall.SetsockoptTimeval(c.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

		n, _, err := syscall.Recvfrom(c.fd, buf, 0)
		if err != nil {
			if errno, ok := err.(syscall.Errno); ok && errno == syscall.EAGAIN {
				continue
			}
			continue
		}

		if n < IPHeaderSize+TCPHeaderSize {
			continue
		}

		// Parse and filter
		ipHdr := parseIPHeader(buf[:n])
		if ipHdr == nil || ipHdr.Protocol != IPPROTO_TCP {
			continue
		}

		// Check if from our peer
		if ipHdr.SrcIP[0] != c.remoteIP[0] || ipHdr.SrcIP[1] != c.remoteIP[1] || 
			ipHdr.SrcIP[2] != c.remoteIP[2] || ipHdr.SrcIP[3] != c.remoteIP[3] {
			continue
		}

		tcpHdr := parseTCPHeader(buf[IPHeaderSize:n])
		if tcpHdr == nil || tcpHdr.SrcPort != c.dstPort || tcpHdr.DstPort != c.srcPort {
			continue
		}

		// Handle SYN-ACK for handshake
		if tcpHdr.Flags&(SYN|ACK) == (SYN | ACK) {
			c.mu.Lock()
			c.ackNum = tcpHdr.SeqNum + 1
			c.mu.Unlock()
			continue
		}

		// Extract payload
		headerLen := int(tcpHdr.DataOffset) * 4
		if headerLen < TCPHeaderSize {
			headerLen = TCPHeaderSize
		}
		payloadStart := IPHeaderSize + headerLen
		if n > payloadStart {
			payload := make([]byte, n-payloadStart)
			copy(payload, buf[payloadStart:n])
			
			c.mu.Lock()
			c.ackNum = tcpHdr.SeqNum + uint32(len(payload))
			c.mu.Unlock()

			select {
			case c.recvQueue <- payload:
			default:
			}
		}
	}
}

// receiverListener receives packets (for listener connections)
func (c *RawConn) receiverListener(fd int, l *RawListener) {
	buf := make([]byte, RawMaxPacketSize)
	for {
		if atomic.LoadInt32(&c.closed) != 0 {
			return
		}

		tv := syscall.Timeval{Sec: 1, Usec: 0}
		syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if errno, ok := err.(syscall.Errno); ok && errno == syscall.EAGAIN {
				continue
			}
			continue
		}

		if n < IPHeaderSize+TCPHeaderSize {
			continue
		}

		// Parse and filter
		ipHdr := parseIPHeader(buf[:n])
		if ipHdr == nil || ipHdr.Protocol != IPPROTO_TCP {
			continue
		}

		// Check if from our peer
		if ipHdr.SrcIP[0] != c.remoteIP[0] || ipHdr.SrcIP[1] != c.remoteIP[1] ||
			ipHdr.SrcIP[2] != c.remoteIP[2] || ipHdr.SrcIP[3] != c.remoteIP[3] {
			continue
		}

		tcpHdr := parseTCPHeader(buf[IPHeaderSize:n])
		if tcpHdr == nil || tcpHdr.SrcPort != c.dstPort || tcpHdr.DstPort != c.srcPort {
			continue
		}

		// Extract payload
		headerLen := int(tcpHdr.DataOffset) * 4
		if headerLen < TCPHeaderSize {
			headerLen = TCPHeaderSize
		}
		payloadStart := IPHeaderSize + headerLen
		if n > payloadStart {
			payload := make([]byte, n-payloadStart)
			copy(payload, buf[payloadStart:n])
			
			c.mu.Lock()
			c.ackNum = tcpHdr.SeqNum + uint32(len(payload))
			c.mu.Unlock()

			select {
			case c.recvQueue <- payload:
			default:
			}
		}
	}
}

// Close closes the connection
func (c *RawConn) Close() error {
	if !atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		return nil
	}

	// Send FIN
	c.sendPacket(FIN|ACK, nil)

	if !c.isListener {
		syscall.Close(c.fd)
	}

	c.closeOnce.Do(func() {
		close(c.recvQueue)
	})

	return nil
}

// LocalAddr returns local address
func (c *RawConn) LocalAddr() net.Addr {
	return c.localAddr
}

// RemoteAddr returns remote address
func (c *RawConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// buildIPHeader builds IP header
func (c *RawConn) buildIPHeader(totalLen int) *IPHeader {
	return &IPHeader{
		Version:  4,
		IHL:      5,
		TOS:      0,
		TotalLen: uint16(IPHeaderSize + totalLen),
		ID:       uint16(randomSeq() & 0xFFFF),
		Flags:    0x40, // DF (Don't Fragment)
		TTL:      64,
		Protocol: IPPROTO_TCP,
		SrcIP:    c.localIP,
		DstIP:    c.remoteIP,
	}
}

// buildTCPHeader builds TCP header
func (c *RawConn) buildTCPHeader(flags uint8, data []byte) *TCPHeader {
	return &TCPHeader{
		SrcPort:    c.srcPort,
		DstPort:    c.dstPort,
		SeqNum:     c.seqNum,
		AckNum:     c.ackNum,
		DataOffset: 5,
		Flags:      flags,
		Window:     65535,
	}
}

// Helper structures
type IPHeader struct {
	Version  uint8
	IHL      uint8
	TOS      uint8
	TotalLen uint16
	ID       uint16
	Flags    uint8
	TTL      uint8
	Protocol uint8
	Checksum uint16
	SrcIP    [4]byte
	DstIP    [4]byte
}

type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8
	Flags      uint8
	Window     uint16
	Checksum   uint16
}

// Serialization functions
func serializeIPHeader(h *IPHeader) []byte {
	b := make([]byte, IPHeaderSize)
	b[0] = (h.Version << 4) | h.IHL
	b[1] = h.TOS
	binary.BigEndian.PutUint16(b[2:4], h.TotalLen)
	binary.BigEndian.PutUint16(b[4:6], h.ID)
	binary.BigEndian.PutUint16(b[6:8], uint16(h.Flags)<<13)
	b[8] = h.TTL
	b[9] = h.Protocol
	copy(b[12:16], h.SrcIP[:])
	copy(b[16:20], h.DstIP[:])
	
	// Calculate checksum
	h.Checksum = ipChecksum(b)
	binary.BigEndian.PutUint16(b[10:12], h.Checksum)
	
	return b
}

func serializeTCPHeader(h *TCPHeader, data []byte, srcIP, dstIP []byte) []byte {
	b := make([]byte, TCPHeaderSize)
	binary.BigEndian.PutUint16(b[0:2], h.SrcPort)
	binary.BigEndian.PutUint16(b[2:4], h.DstPort)
	binary.BigEndian.PutUint32(b[4:8], h.SeqNum)
	binary.BigEndian.PutUint32(b[8:12], h.AckNum)
	b[12] = h.DataOffset << 4
	b[13] = h.Flags
	binary.BigEndian.PutUint16(b[14:16], h.Window)
	binary.BigEndian.PutUint16(b[18:20], 0) // Urgent pointer
	
	// Calculate checksum with pseudo-header
	h.Checksum = tcpChecksum(srcIP, dstIP, append(b, data...))
	binary.BigEndian.PutUint16(b[16:18], h.Checksum)
	
	return append(b, data...)
}

// Parsing functions
func parseIPHeader(data []byte) *IPHeader {
	if len(data) < IPHeaderSize {
		return nil
	}
	return &IPHeader{
		Version:  data[0] >> 4,
		IHL:      data[0] & 0x0F,
		TOS:      data[1],
		TotalLen: binary.BigEndian.Uint16(data[2:4]),
		ID:       binary.BigEndian.Uint16(data[4:6]),
		TTL:      data[8],
		Protocol: data[9],
		Checksum: binary.BigEndian.Uint16(data[10:12]),
		SrcIP:    [4]byte{data[12], data[13], data[14], data[15]},
		DstIP:    [4]byte{data[16], data[17], data[18], data[19]},
	}
}

func parseTCPHeader(data []byte) *TCPHeader {
	if len(data) < TCPHeaderSize {
		return nil
	}
	return &TCPHeader{
		SrcPort:    binary.BigEndian.Uint16(data[0:2]),
		DstPort:    binary.BigEndian.Uint16(data[2:4]),
		SeqNum:     binary.BigEndian.Uint32(data[4:8]),
		AckNum:     binary.BigEndian.Uint32(data[8:12]),
		DataOffset: data[12] >> 4,
		Flags:      data[13],
		Window:     binary.BigEndian.Uint16(data[14:16]),
		Checksum:   binary.BigEndian.Uint16(data[16:18]),
	}
}

// Checksum functions
func ipChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		if i == 10 { // Skip checksum field
			continue
		}
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func tcpChecksum(srcIP, dstIP, tcpData []byte) uint16 {
	// Pseudo-header
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], srcIP)
	copy(pseudo[4:8], dstIP)
	pseudo[9] = IPPROTO_TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcpData)))
	
	data := append(pseudo, tcpData...)
	
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		// Skip TCP checksum field (offset 16-17 in TCP header, which starts at pseudo-header offset 12)
		if i >= 12 && (i-12) >= 16 && (i-12) < 18 {
			continue
		}
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// Helper functions
func randomSeq() uint32 {
	return uint32(time.Now().UnixNano() & 0xFFFFFFFF)
}

func getLocalAddr(remote *net.TCPAddr) (*net.TCPAddr, error) {
	// Connect to remote to determine local address and interface
	conn, err := net.DialTimeout("tcp", remote.String(), 3*time.Second)
	if err != nil {
		// If connection fails, get default route interface
		// Use loopback as fallback
		addrs, _ := net.InterfaceAddrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipv4 := ipnet.IP.To4(); ipv4 != nil {
					// Use random ephemeral port
					return &net.TCPAddr{
						IP:   ipv4,
						Port: 1024 + int(randomSeq()%64512), // Ephemeral port range
					}, nil
				}
			}
		}
		// Ultimate fallback
		return &net.TCPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 1024 + int(randomSeq()%64512),
		}, nil
	}
	defer conn.Close()
	
	localAddr := conn.LocalAddr().(*net.TCPAddr)
	// Use the actual local IP but pick a random ephemeral port
	return &net.TCPAddr{
		IP:   localAddr.IP,
		Port: 1024 + int(randomSeq()%64512), // Random ephemeral port
	}, nil
}

// SetDeadline sets deadline (stub for compatibility)
func (c *RawConn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline sets read deadline (stub for compatibility)
func (c *RawConn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline sets write deadline (stub for compatibility)
func (c *RawConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// Ensure RawConn implements required interface
var _ interface {
	WritePacket([]byte) error
	ReadPacket() ([]byte, error)
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
} = (*RawConn)(nil)
