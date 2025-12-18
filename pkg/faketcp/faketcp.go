package faketcp

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
)

const (
	// TCP header flags
	FIN = 0x01
	SYN = 0x02
	RST = 0x04
	PSH = 0x08
	ACK = 0x10
	URG = 0x20

	// TCP header size (minimum, without options)
	TCPHeaderSize = 20
	// IP header size (minimum, without options)
	IPHeaderSize = 20
	// Maximum packet size
	MaxPacketSize = 1500
	// Maximum payload size (MTU - IP - TCP headers)
	MaxPayloadSize = MaxPacketSize - IPHeaderSize - TCPHeaderSize
)

// TCPHeader represents a minimal TCP header
type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8  // 4 bits
	Flags      uint8
	Window     uint16
	Checksum   uint16
	UrgentPtr  uint16
}

// IPHeader represents a minimal IPv4 header
type IPHeader struct {
	Version    uint8  // 4 bits
	IHL        uint8  // 4 bits (Internet Header Length)
	TOS        uint8  // Type of Service
	TotalLen   uint16
	ID         uint16
	Flags      uint8  // 3 bits
	FragOffset uint16 // 13 bits
	TTL        uint8
	Protocol   uint8
	Checksum   uint16
	SrcIP      [4]byte
	DstIP      [4]byte
}

// Conn represents a fake TCP connection over UDP
type Conn struct {
	udpConn     *net.UDPConn
	rawConn     int // raw socket file descriptor
	localAddr   *net.UDPAddr
	remoteAddr  *net.UDPAddr
	srcPort     uint16
	dstPort     uint16
	seqNum      uint32
	ackNum      uint32
	mu          sync.Mutex
	isConnected bool // true if UDP socket is connected, false if shared listener socket
	recvQueue   chan []byte // for listener connections
}

// NewConn creates a new fake TCP connection
func NewConn(udpConn *net.UDPConn, remoteAddr *net.UDPAddr, isConnected bool) (*Conn, error) {
	localAddr := udpConn.LocalAddr().(*net.UDPAddr)
	
	conn := &Conn{
		udpConn:     udpConn,
		localAddr:   localAddr,
		remoteAddr:  remoteAddr,
		srcPort:     uint16(localAddr.Port),
		dstPort:     uint16(remoteAddr.Port),
		seqNum:      uint32(time.Now().Unix()), // Initial sequence number
		ackNum:      0,
		isConnected: isConnected,
	}
	
	return conn, nil
}

// Dial creates a fake TCP connection to the remote address
func Dial(remoteAddr string, timeout time.Duration) (*Conn, error) {
	// Parse remote address
	raddr, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %v", err)
	}
	
	// Create UDP connection (connected socket)
	udpConn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial UDP: %v", err)
	}
	
	conn, err := NewConn(udpConn, raddr, true)
	if err != nil {
		udpConn.Close()
		return nil, err
	}
	
	return conn, nil
}

// Listen creates a listener for fake TCP connections
func Listen(addr string) (*Listener, error) {
	// Parse address
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %v", err)
	}
	
	// Create UDP listener
	udpConn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen UDP: %v", err)
	}
	
	return &Listener{
		udpConn: udpConn,
		connMap: make(map[string]*Conn),
	}, nil
}

// Listener listens for fake TCP connections
type Listener struct {
	udpConn *net.UDPConn
	connMap map[string]*Conn
	mu      sync.RWMutex
}

// Accept accepts a new connection (blocks until packet arrives)
func (l *Listener) Accept() (*Conn, error) {
	buf := make([]byte, MaxPacketSize)
	
	for {
		n, remoteAddr, err := l.udpConn.ReadFromUDP(buf)
		if err != nil {
			return nil, err
		}
		
		if n < TCPHeaderSize {
			continue // Invalid packet
		}
		
		// Extract TCP header to get source port
		tcpHeader := parseTCPHeader(buf[:TCPHeaderSize])
		
		// Create connection key (remote IP:port)
		connKey := remoteAddr.String()
		
		l.mu.Lock()
		conn, exists := l.connMap[connKey]
		if !exists {
			// New connection
			conn = &Conn{
				udpConn:     l.udpConn,
				localAddr:   l.udpConn.LocalAddr().(*net.UDPAddr),
				remoteAddr:  remoteAddr,
				srcPort:     uint16(l.udpConn.LocalAddr().(*net.UDPAddr).Port),
				dstPort:     tcpHeader.SrcPort,
				seqNum:      uint32(time.Now().Unix()),
				ackNum:      tcpHeader.SeqNum + uint32(n-TCPHeaderSize),
				isConnected: false, // Shared listener socket
				recvQueue:   make(chan []byte, 100),
			}
			l.connMap[connKey] = conn
			
			// Extract and queue first payload
			if n > TCPHeaderSize {
				payload := make([]byte, n-TCPHeaderSize)
				copy(payload, buf[TCPHeaderSize:n])
				conn.recvQueue <- payload
			}
			
			l.mu.Unlock()
			return conn, nil
		}
		l.mu.Unlock()
		
		// Existing connection - queue payload
		if n > TCPHeaderSize {
			payload := make([]byte, n-TCPHeaderSize)
			copy(payload, buf[TCPHeaderSize:n])
			select {
			case conn.recvQueue <- payload:
			default:
				// Queue full, drop packet
			}
		}
	}
}

// Close closes the listener
func (l *Listener) Close() error {
	return l.udpConn.Close()
}

// Addr returns the listener's network address
func (l *Listener) Addr() net.Addr {
	return l.udpConn.LocalAddr()
}

// WritePacket sends data with fake TCP header
func (c *Conn) WritePacket(data []byte) error {
	if len(data) > MaxPayloadSize {
		return fmt.Errorf("packet too large: %d > %d", len(data), MaxPayloadSize)
	}
	
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Build fake TCP header
	tcpHeader := c.buildTCPHeader(len(data))
	headerBytes := c.serializeTCPHeader(tcpHeader)
	
	// Combine header and data
	packet := make([]byte, TCPHeaderSize+len(data))
	copy(packet[:TCPHeaderSize], headerBytes)
	copy(packet[TCPHeaderSize:], data)
	
	// Send via UDP
	var err error
	if c.isConnected {
		// Connected socket - use Write
		_, err = c.udpConn.Write(packet)
	} else {
		// Shared listener socket - use WriteToUDP
		_, err = c.udpConn.WriteToUDP(packet, c.remoteAddr)
	}
	if err != nil {
		return fmt.Errorf("failed to send packet: %v", err)
	}
	
	// Update sequence number
	c.seqNum += uint32(len(data))
	
	return nil
}

// ReadPacket receives data and strips fake TCP header
func (c *Conn) ReadPacket() ([]byte, error) {
	if !c.isConnected {
		// Listener connection - read from queue
		select {
		case payload := <-c.recvQueue:
			return payload, nil
		case <-time.After(30 * time.Second):
			return nil, fmt.Errorf("read timeout")
		}
	}
	
	// Connected socket - read directly
	buf := make([]byte, MaxPacketSize)
	n, err := c.udpConn.Read(buf)
	if err != nil {
		return nil, err
	}
	
	if n < TCPHeaderSize {
		return nil, fmt.Errorf("packet too small: %d bytes", n)
	}
	
	// Parse TCP header
	tcpHeader := parseTCPHeader(buf[:TCPHeaderSize])
	
	c.mu.Lock()
	// Update our ack number based on received sequence
	c.ackNum = tcpHeader.SeqNum + uint32(n-TCPHeaderSize)
	c.mu.Unlock()
	
	// Return payload (skip TCP header)
	payload := make([]byte, n-TCPHeaderSize)
	copy(payload, buf[TCPHeaderSize:n])
	
	return payload, nil
}

// buildTCPHeader constructs a fake TCP header
func (c *Conn) buildTCPHeader(dataLen int) *TCPHeader {
	return &TCPHeader{
		SrcPort:    c.srcPort,
		DstPort:    c.dstPort,
		SeqNum:     c.seqNum,
		AckNum:     c.ackNum,
		DataOffset: 5, // 5 * 4 = 20 bytes (no options)
		Flags:      PSH | ACK,
		Window:     65535,
		Checksum:   0, // Will be calculated
		UrgentPtr:  0,
	}
}

// serializeTCPHeader converts TCP header to bytes
func (c *Conn) serializeTCPHeader(h *TCPHeader) []byte {
	buf := make([]byte, TCPHeaderSize)
	
	binary.BigEndian.PutUint16(buf[0:2], h.SrcPort)
	binary.BigEndian.PutUint16(buf[2:4], h.DstPort)
	binary.BigEndian.PutUint32(buf[4:8], h.SeqNum)
	binary.BigEndian.PutUint32(buf[8:12], h.AckNum)
	
	// Data offset (4 bits) + reserved (3 bits) + flags (9 bits, but we use 8)
	buf[12] = (h.DataOffset << 4)
	buf[13] = h.Flags
	
	binary.BigEndian.PutUint16(buf[14:16], h.Window)
	binary.BigEndian.PutUint16(buf[16:18], h.Checksum)
	binary.BigEndian.PutUint16(buf[18:20], h.UrgentPtr)
	
	// Calculate checksum (simplified - set to 0 for now)
	// In production, you'd calculate a proper TCP checksum
	checksum := c.calculateChecksum(buf)
	binary.BigEndian.PutUint16(buf[16:18], checksum)
	
	return buf
}

// parseTCPHeader parses bytes into TCP header
func parseTCPHeader(buf []byte) *TCPHeader {
	if len(buf) < TCPHeaderSize {
		return nil
	}
	
	return &TCPHeader{
		SrcPort:    binary.BigEndian.Uint16(buf[0:2]),
		DstPort:    binary.BigEndian.Uint16(buf[2:4]),
		SeqNum:     binary.BigEndian.Uint32(buf[4:8]),
		AckNum:     binary.BigEndian.Uint32(buf[8:12]),
		DataOffset: buf[12] >> 4,
		Flags:      buf[13],
		Window:     binary.BigEndian.Uint16(buf[14:16]),
		Checksum:   binary.BigEndian.Uint16(buf[16:18]),
		UrgentPtr:  binary.BigEndian.Uint16(buf[18:20]),
	}
}

// calculateChecksum calculates TCP checksum (simplified version)
func (c *Conn) calculateChecksum(data []byte) uint16 {
	// Simplified checksum - just return 0 for now
	// In production, implement proper TCP checksum with pseudo-header
	// This is acceptable since we're just disguising, not implementing real TCP
	return 0
}

// Close closes the connection
func (c *Conn) Close() error {
	if c.rawConn > 0 {
		syscall.Close(c.rawConn)
	}
	// Don't close udpConn if it's shared with listener
	return nil
}

// LocalAddr returns the local address
func (c *Conn) LocalAddr() net.Addr {
	return c.localAddr
}

// RemoteAddr returns the remote address
func (c *Conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// SetDeadline sets read and write deadlines
func (c *Conn) SetDeadline(t time.Time) error {
	return c.udpConn.SetDeadline(t)
}

// SetReadDeadline sets read deadline
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.udpConn.SetReadDeadline(t)
}

// SetWriteDeadline sets write deadline
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.udpConn.SetWriteDeadline(t)
}
