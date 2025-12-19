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
	
	// Read timeout duration for making blocking reads interruptible
	ReadTimeoutDuration = 1 * time.Second
	// Listener read timeout for queue operations (longer timeout for actual data)
	ListenerReadTimeout = 30 * time.Second
	// Handshake timeout for SYN/SYN-ACK/ACK
	HandshakeTimeout = 3 * time.Second
	// Channel close delay to allow pending writes to complete
	ChannelCloseDelay = 100 * time.Millisecond
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
	Options    []byte
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
	localAddr   *net.UDPAddr
	remoteAddr  *net.UDPAddr
	srcPort     uint16
	dstPort     uint16
	seqNum      uint32
	ackNum      uint32
	mu          sync.Mutex
	isConnected bool // true if UDP socket is connected, false if shared listener socket
	recvQueue   chan []byte // for listener connections
	closed      int32       // atomic flag: 1 if connection is closed, 0 otherwise
	closeOnce   sync.Once   // ensures channel is closed only once
}

// NewConn creates a new fake TCP connection
func NewConn(udpConn *net.UDPConn, remoteAddr *net.UDPAddr, isConnected bool) (*Conn, error) {
	localAddr := udpConn.LocalAddr().(*net.UDPAddr)
    
	// Generate a random initial sequence number (ISN)
	isn, err := randomUint32()
	if err != nil {
		return nil, err
	}

	conn := &Conn{
		udpConn:     udpConn,
		localAddr:   localAddr,
		remoteAddr:  remoteAddr,
		srcPort:     uint16(localAddr.Port),
		dstPort:     uint16(remoteAddr.Port),
		seqNum:      isn, // Initial sequence number (random)
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

	// Perform simple TCP-like three-way handshake: send SYN, wait SYN-ACK, send ACK
	// Build SYN
	synHdr := conn.buildTCPHeader(0)
	synHdr.Flags = SYN
	synHdr.Options = synHdr.Options // keep options
	synBytes := conn.serializeTCPHeader(synHdr)
	if _, err := conn.udpConn.Write(synBytes); err != nil {
		conn.udpConn.Close()
		return nil, fmt.Errorf("failed to send SYN: %v", err)
	}
	// Advance seq by 1 for SYN
	conn.seqNum += 1

	// Wait for SYN-ACK
	buf := make([]byte, MaxPacketSize)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn.udpConn.SetReadDeadline(time.Now().Add(ReadTimeoutDuration))
		n, err := conn.udpConn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			conn.udpConn.Close()
			return nil, fmt.Errorf("handshake read error: %v", err)
		}
		hdr := parseTCPHeader(buf[:n])
		if hdr == nil {
			continue
		}
		if hdr.Flags&(SYN|ACK) == (SYN | ACK) {
			// Set ack and send ACK back
			conn.ackNum = hdr.SeqNum + 1
			ackHdr := conn.buildTCPHeader(0)
			ackHdr.Flags = ACK
			ackHdr.AckNum = conn.ackNum
			ackBytes := conn.serializeTCPHeader(ackHdr)
			conn.udpConn.Write(ackBytes)
			return conn, nil
		}
	}

	// Handshake timed out; still return connection (best-effort disguise)
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
		// Set read deadline to allow for interruption
		l.udpConn.SetReadDeadline(time.Now().Add(ReadTimeoutDuration))
		
		n, remoteAddr, err := l.udpConn.ReadFromUDP(buf)
		if err != nil {
			// Check if it's a timeout, if so continue to allow for shutdown check
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return nil, err
		}
		
		if n < TCPHeaderSize {
			continue // Invalid packet
		}

		// Parse full TCP header (may contain options)
		tcpHeader := parseTCPHeader(buf[:n])
		if tcpHeader == nil {
			continue
		}

		// Create connection key (remote IP:port)
		connKey := remoteAddr.String()

		l.mu.Lock()
		conn, exists := l.connMap[connKey]
		if !exists {
			// New connection - handle SYN handshake if present
			if tcpHeader.Flags&SYN != 0 {
				// Create connection object but don't publish until handshake completes
				serverIsn, _ := randomUint32()
				newConn := &Conn{
					udpConn:     l.udpConn,
					localAddr:   l.udpConn.LocalAddr().(*net.UDPAddr),
					remoteAddr:  remoteAddr,
					srcPort:     uint16(l.udpConn.LocalAddr().(*net.UDPAddr).Port),
					dstPort:     tcpHeader.SrcPort,
					seqNum:      serverIsn,
					ackNum:      tcpHeader.SeqNum + 1,
					isConnected: false,
					recvQueue:   make(chan []byte, 100),
				}

				// Send SYN-ACK
				synAck := &TCPHeader{
					SrcPort: newConn.srcPort,
					DstPort: newConn.dstPort,
					SeqNum:  newConn.seqNum,
					AckNum:  newConn.ackNum,
					Flags:   SYN | ACK,
					Window:  65535,
					Options: newConn.buildTCPHeader(0).Options,
				}
				synAckBytes := serializeTCPHeaderStatic(synAck)
				l.udpConn.WriteToUDP(synAckBytes, remoteAddr)

				// Wait for ACK from client (handshake)
				deadline := time.Now().Add(HandshakeTimeout)
				handshakeDone := false
				for !handshakeDone && time.Now().Before(deadline) {
					l.udpConn.SetReadDeadline(time.Now().Add(ReadTimeoutDuration))
					n2, r2, err := l.udpConn.ReadFromUDP(buf)
					if err != nil {
						if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
							continue
						}
						break
					}
					if r2.String() != remoteAddr.String() {
						// Not the same peer; ignore (will be handled in outer loop)
						continue
					}
					hdr := parseTCPHeader(buf[:n2])
					if hdr == nil {
						continue
					}
					if hdr.Flags&ACK != 0 && hdr.AckNum == newConn.seqNum+1 {
						// Handshake complete
						newConn.seqNum += 1
						// If there's payload after header, queue it
						headerLen := int(hdr.DataOffset) * 4
						if headerLen < TCPHeaderSize {
							headerLen = TCPHeaderSize
						}
						if n2 > headerLen {
							payload := make([]byte, n2-headerLen)
							copy(payload, buf[headerLen:n2])
							newConn.recvQueue <- payload
						}
						// Publish connection and return
						l.connMap[connKey] = newConn
						l.mu.Unlock()
						return newConn, nil
					}
				}

				// Handshake timed out or failed: still publish connection to allow further packets
				l.connMap[connKey] = newConn
				l.mu.Unlock()
				return newConn, nil
			}

			// Not a SYN or policy: create a connection and queue payload
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

			// Extract and queue first payload (respect header length)
			headerLen := int(tcpHeader.DataOffset) * 4
			if headerLen < TCPHeaderSize {
				headerLen = TCPHeaderSize
			}
			if n > headerLen {
				payload := make([]byte, n-headerLen)
				copy(payload, buf[headerLen:n])
				conn.recvQueue <- payload
			}

			l.mu.Unlock()
			return conn, nil
		}
		l.mu.Unlock()

		// Existing connection - queue payload based on header length
		if n > int(tcpHeader.DataOffset)*4 {
			headerLen := int(tcpHeader.DataOffset) * 4
			if headerLen < TCPHeaderSize {
				headerLen = TCPHeaderSize
			}
			payload := make([]byte, n-headerLen)
			copy(payload, buf[headerLen:n])

			// Check if connection is closed before attempting to send (using atomic read)
			if atomic.LoadInt32(&conn.closed) == 0 {
				// Use recover to handle the rare case where channel is closed between check and send
				func() {
					defer func() {
						if r := recover(); r != nil {
							// Channel was closed, silently drop packet
							log.Printf("WARNING: Connection closed for %s, dropping packet (%d bytes)", connKey, len(payload))
						}
					}()
					select {
					case conn.recvQueue <- payload:
						// Successfully queued
					default:
						// Queue full, drop packet and log
						log.Printf("WARNING: Receive queue full for %s, dropping packet (%d bytes)", connKey, len(payload))
					}
				}()
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
	// Segment data by typical MSS to look like TCP segments
	const defaultMSS = 1460

	c.mu.Lock()
	defer c.mu.Unlock()

	total := len(data)
	sent := 0
	for sent < total {
		// Build header for this segment
		remaining := total - sent
		segLen := defaultMSS
		if remaining < segLen {
			segLen = remaining
		}

		seg := data[sent : sent+segLen]
		tcpHeader := c.buildTCPHeader(len(seg))
		headerBytes := c.serializeTCPHeader(tcpHeader)

		packet := make([]byte, len(headerBytes)+len(seg))
		copy(packet[:len(headerBytes)], headerBytes)
		copy(packet[len(headerBytes):], seg)

		var err error
		if c.isConnected {
			_, err = c.udpConn.Write(packet)
		} else {
			_, err = c.udpConn.WriteToUDP(packet, c.remoteAddr)
		}
		if err != nil {
			return fmt.Errorf("failed to send packet: %v", err)
		}

		// Update sequence number and counters
		c.seqNum += uint32(len(seg))
		sent += segLen
	}

	return nil
}

// ReadPacket receives data and strips fake TCP header
func (c *Conn) ReadPacket() ([]byte, error) {
	if !c.isConnected {
		// Listener connection - read from queue with proper closed check
		select {
		case payload, ok := <-c.recvQueue:
			if !ok {
				return nil, fmt.Errorf("connection closed")
			}
			return payload, nil
		case <-time.After(ListenerReadTimeout):
			// Check if closed during timeout (using atomic read)
			if atomic.LoadInt32(&c.closed) != 0 {
				return nil, fmt.Errorf("connection closed")
			}
			return nil, fmt.Errorf("read timeout")
		}
	}
	
	// Connected socket - read directly with deadline to allow interruption
	c.udpConn.SetReadDeadline(time.Now().Add(ReadTimeoutDuration))

	buf := make([]byte, MaxPacketSize)
	n, err := c.udpConn.Read(buf)
	if err != nil {
		// Check if it's a timeout - return a specific error to allow caller to retry
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, netErr
		}
		return nil, err
	}
	if n < TCPHeaderSize {
		return nil, fmt.Errorf("packet too small: %d bytes", n)
	}

	// Parse full header (may include options)
	tcpHeader := parseTCPHeader(buf[:n])
	if tcpHeader == nil {
		return nil, fmt.Errorf("failed to parse tcp header")
	}

	headerLen := int(tcpHeader.DataOffset) * 4
	if headerLen < TCPHeaderSize {
		headerLen = TCPHeaderSize
	}
	if n < headerLen {
		return nil, fmt.Errorf("packet smaller than header: %d < %d", n, headerLen)
	}

	payloadLen := n - headerLen

	c.mu.Lock()
	// Update our ack number based on received sequence
	c.ackNum = tcpHeader.SeqNum + uint32(payloadLen)
	c.mu.Unlock()

	// Return payload (skip TCP header)
	payload := make([]byte, payloadLen)
	copy(payload, buf[headerLen:n])

	return payload, nil
}

// buildTCPHeader constructs a fake TCP header
func (c *Conn) buildTCPHeader(dataLen int) *TCPHeader {
	// Build common TCP options to resemble real TCP stacks
	opts := make([]byte, 0)

	// MSS (kind=2, len=4)
	mss := uint16(1460)
	mssOpt := make([]byte, 4)
	mssOpt[0] = 2
	mssOpt[1] = 4
	binary.BigEndian.PutUint16(mssOpt[2:], mss)
	opts = append(opts, mssOpt...)

	// NOP for padding
	opts = append(opts, 1)

	// Window scale (kind=3, len=3)
	opts = append(opts, 3, 3, 7)

	// SACK permitted (kind=4, len=2)
	opts = append(opts, 4, 2)

	// NOP then Timestamp (kind=8, len=10)
	tsOpt := make([]byte, 10)
	tsOpt[0] = 8
	tsOpt[1] = 10
	// ts value pseudo-random
	if v, err := randomUint32(); err == nil {
		binary.BigEndian.PutUint32(tsOpt[2:], v)
	}
	binary.BigEndian.PutUint32(tsOpt[6:], 0)
	opts = append(opts, 1) // NOP before TS
	opts = append(opts, tsOpt...)

	return &TCPHeader{
		SrcPort:    c.srcPort,
		DstPort:    c.dstPort,
		SeqNum:     c.seqNum,
		AckNum:     c.ackNum,
		DataOffset: 5, // will be adjusted in serialize
		Flags:      PSH | ACK,
		Window:     65535,
		Checksum:   0,
		UrgentPtr:  0,
		Options:    opts,
	}
}

// serializeTCPHeader converts TCP header to bytes
func (c *Conn) serializeTCPHeader(h *TCPHeader) []byte {
	// Base header
	base := make([]byte, TCPHeaderSize)

	binary.BigEndian.PutUint16(base[0:2], h.SrcPort)
	binary.BigEndian.PutUint16(base[2:4], h.DstPort)
	binary.BigEndian.PutUint32(base[4:8], h.SeqNum)
	binary.BigEndian.PutUint32(base[8:12], h.AckNum)

	// Options length in 32-bit words
	optLen := 0
	if len(h.Options) > 0 {
		// pad options to 4-byte boundary
		pad := (4 - (len(h.Options) % 4)) % 4
		if pad > 0 {
			h.Options = append(h.Options, make([]byte, pad)...)
		}
		optLen = len(h.Options)
	}

	dataOffsetWords := uint8(5 + (optLen / 4))
	base[12] = (dataOffsetWords << 4)
	base[13] = h.Flags

	binary.BigEndian.PutUint16(base[14:16], h.Window)
	binary.BigEndian.PutUint16(base[18:20], h.UrgentPtr)

	// Simplified checksum: use a non-zero pseudo-random value to avoid trivial fingerprint
	cs, _ := randomUint16()
	if cs == 0 {
		cs = 1
	}
	binary.BigEndian.PutUint16(base[16:18], cs)

	if optLen == 0 {
		return base
	}

	header := make([]byte, TCPHeaderSize+optLen)
	copy(header[:TCPHeaderSize], base)
	copy(header[TCPHeaderSize:], h.Options[:optLen])
	return header
}

// parseTCPHeader parses bytes into TCP header (supports options)
func parseTCPHeader(buf []byte) *TCPHeader {
	if len(buf) < TCPHeaderSize {
		return nil
	}

	dataOffset := buf[12] >> 4
	headerLen := int(dataOffset) * 4
	if headerLen < TCPHeaderSize {
		headerLen = TCPHeaderSize
	}
	if len(buf) < headerLen {
		// caller didn't supply full header
		return nil
	}

	h := &TCPHeader{
		SrcPort:    binary.BigEndian.Uint16(buf[0:2]),
		DstPort:    binary.BigEndian.Uint16(buf[2:4]),
		SeqNum:     binary.BigEndian.Uint32(buf[4:8]),
		AckNum:     binary.BigEndian.Uint32(buf[8:12]),
		DataOffset: dataOffset,
		Flags:      buf[13],
		Window:     binary.BigEndian.Uint16(buf[14:16]),
		Checksum:   binary.BigEndian.Uint16(buf[16:18]),
		UrgentPtr:  binary.BigEndian.Uint16(buf[18:20]),
	}

	if headerLen > TCPHeaderSize {
		opts := make([]byte, headerLen-TCPHeaderSize)
		copy(opts, buf[TCPHeaderSize:headerLen])
		h.Options = opts
	}
	return h
}

// randomUint16 returns a random uint16
func randomUint16() (uint16, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(0x10000))
	if err != nil {
		return 0, err
	}
	return uint16(n.Int64()), nil
}

// randomUint32 returns a random uint32
func randomUint32() (uint32, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(0x100000000))
	if err != nil {
		return 0, err
	}
	return uint32(n.Int64()), nil
}

// serializeTCPHeaderStatic serializes a TCPHeader without requiring a Conn receiver
func serializeTCPHeaderStatic(h *TCPHeader) []byte {
	base := make([]byte, TCPHeaderSize)

	binary.BigEndian.PutUint16(base[0:2], h.SrcPort)
	binary.BigEndian.PutUint16(base[2:4], h.DstPort)
	binary.BigEndian.PutUint32(base[4:8], h.SeqNum)
	binary.BigEndian.PutUint32(base[8:12], h.AckNum)

	optLen := 0
	if len(h.Options) > 0 {
		pad := (4 - (len(h.Options) % 4)) % 4
		if pad > 0 {
			h.Options = append(h.Options, make([]byte, pad)...)
		}
		optLen = len(h.Options)
	}
	dataOffsetWords := uint8(5 + (optLen / 4))
	base[12] = (dataOffsetWords << 4)
	base[13] = h.Flags

	binary.BigEndian.PutUint16(base[14:16], h.Window)
	binary.BigEndian.PutUint16(base[18:20], h.UrgentPtr)

	cs, _ := randomUint16()
	if cs == 0 {
		cs = 1
	}
	binary.BigEndian.PutUint16(base[16:18], cs)

	if optLen == 0 {
		return base
	}
	header := make([]byte, TCPHeaderSize+optLen)
	copy(header[:TCPHeaderSize], base)
	copy(header[TCPHeaderSize:], h.Options[:optLen])
	return header
}

// Close closes the connection
func (c *Conn) Close() error {
	// Use atomic compare-and-swap to prevent multiple close operations
	// This ensures only ONE goroutine can proceed past this point
	if !atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		// Already closed - return immediately without creating a goroutine
		return nil
	}
	
	// For connected sockets created with Dial(), close the UDP connection
	if c.isConnected {
		return c.udpConn.Close()
	}
	
	// For shared listener sockets, don't close the shared UDP connection
	// but close the receive queue channel after a brief delay to allow pending writes to complete
	if c.recvQueue != nil {
		// Only ONE goroutine is created due to the atomic check above
		// Give pending writes a chance to complete, then close channel exactly once
		go func() {
			time.Sleep(ChannelCloseDelay)
			c.closeOnce.Do(func() {
				close(c.recvQueue)
			})
		}()
	}
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
