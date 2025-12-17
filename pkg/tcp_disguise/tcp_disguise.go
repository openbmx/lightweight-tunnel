package tcp_disguise

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const (
	// MaxPacketSize is the maximum packet size
	MaxPacketSize = 1500
	// HeaderSize is the size of the packet header
	HeaderSize = 4
)

// Conn wraps a TCP connection to send/receive UDP-like packets
type Conn struct {
	conn      net.Conn
	readMutex sync.Mutex
	writeMutex sync.Mutex
}

// NewConn creates a new disguised connection
func NewConn(conn net.Conn) *Conn {
	return &Conn{
		conn: conn,
	}
}

// DialTCP establishes a TCP connection with disguise
func DialTCP(address string, timeout time.Duration) (*Conn, error) {
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil, err
	}
	return NewConn(conn), nil
}

// DialTLS establishes a TLS-encrypted TCP connection
func DialTLS(address string, timeout time.Duration, tlsConfig *tls.Config) (*Conn, error) {
	dialer := &net.Dialer{
		Timeout: timeout,
	}
	
	conn, err := tls.DialWithDialer(dialer, "tcp", address, tlsConfig)
	if err != nil {
		return nil, err
	}
	return NewConn(conn), nil
}

// ListenTCP listens on a TCP port for disguised connections
func ListenTCP(address string) (*Listener, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	return &Listener{listener: listener}, nil
}

// ListenTLS listens on a TCP port with TLS encryption
func ListenTLS(address string, tlsConfig *tls.Config) (*Listener, error) {
	listener, err := tls.Listen("tcp", address, tlsConfig)
	if err != nil {
		return nil, err
	}
	return &Listener{listener: listener}, nil
}

// Listener wraps a TCP listener
type Listener struct {
	listener net.Listener
}

// Accept accepts a new connection
func (l *Listener) Accept() (*Conn, error) {
	conn, err := l.listener.Accept()
	if err != nil {
		return nil, err
	}
	return NewConn(conn), nil
}

// Close closes the listener
func (l *Listener) Close() error {
	return l.listener.Close()
}

// Addr returns the listener's address
func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}

// WritePacket writes a packet with length prefix (like UDP)
func (c *Conn) WritePacket(data []byte) error {
	if len(data) > MaxPacketSize-HeaderSize {
		return errors.New("packet too large")
	}

	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	// Write length prefix
	header := make([]byte, HeaderSize)
	binary.BigEndian.PutUint32(header, uint32(len(data)))

	if _, err := c.conn.Write(header); err != nil {
		return err
	}

	// Write data
	if _, err := c.conn.Write(data); err != nil {
		return err
	}

	return nil
}

// ReadPacket reads a packet with length prefix
func (c *Conn) ReadPacket() ([]byte, error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()

	// Read length prefix
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(c.conn, header); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(header)
	if length > MaxPacketSize-HeaderSize {
		return nil, errors.New("packet too large")
	}

	// Read data
	data := make([]byte, length)
	if _, err := io.ReadFull(c.conn, data); err != nil {
		return nil, err
	}

	return data, nil
}

// Close closes the connection
func (c *Conn) Close() error {
	return c.conn.Close()
}

// LocalAddr returns the local address
func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote address
func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines
func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
