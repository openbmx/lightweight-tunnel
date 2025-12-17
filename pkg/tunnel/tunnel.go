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
	"github.com/openbmx/lightweight-tunnel/pkg/tcp_disguise"
)

const (
	PacketTypeData      = 0x01
	PacketTypeKeepalive = 0x02
)

// Tunnel represents a lightweight tunnel
type Tunnel struct {
	config     *config.Config
	fec        *fec.FEC
	conn       *tcp_disguise.Conn
	tunName    string
	tunFile    *TunDevice
	stopCh     chan struct{}
	wg         sync.WaitGroup
	sendQueue  chan []byte
	recvQueue  chan []byte
}

// NewTunnel creates a new tunnel instance
func NewTunnel(cfg *config.Config) (*Tunnel, error) {
	// Create FEC encoder/decoder
	fecCodec, err := fec.NewFEC(cfg.FECDataShards, cfg.FECParityShards, cfg.MTU/cfg.FECDataShards)
	if err != nil {
		return nil, fmt.Errorf("failed to create FEC: %v", err)
	}

	return &Tunnel{
		config:    cfg,
		fec:       fecCodec,
		stopCh:    make(chan struct{}),
		sendQueue: make(chan []byte, 100),
		recvQueue: make(chan []byte, 100),
	}, nil
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
	} else {
		if err := t.listenServer(); err != nil {
			t.tunFile.Close()
			return fmt.Errorf("failed to start as server: %v", err)
		}
	}

	// Start packet processing goroutines
	t.wg.Add(4)
	go t.tunReader()
	go t.tunWriter()
	go t.netReader()
	go t.netWriter()

	// Start keepalive
	t.wg.Add(1)
	go t.keepalive()

	log.Printf("Tunnel started in %s mode", t.config.Mode)
	return nil
}

// Stop stops the tunnel
func (t *Tunnel) Stop() {
	close(t.stopCh)
	if t.conn != nil {
		t.conn.Close()
	}
	if t.tunFile != nil {
		t.tunFile.Close()
	}
	t.wg.Wait()
	log.Println("Tunnel stopped")
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

// listenServer listens for client connections as server
func (t *Tunnel) listenServer() error {
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

	log.Printf("Waiting for client connection...")
	
	// Accept first connection (single client)
	conn, err := listener.Accept()
	if err != nil {
		listener.Close()
		return err
	}

	t.conn = conn
	log.Printf("Client connected: %s -> %s", conn.RemoteAddr(), conn.LocalAddr())
	
	// Close listener after accepting one connection
	listener.Close()
	return nil
}

// tunReader reads packets from TUN device and queues them for sending
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
			if !isClosed(t.stopCh) {
				log.Printf("TUN read error: %v", err)
			}
			return
		}

		if n > 0 {
			// Copy packet data
			packet := make([]byte, n)
			copy(packet, buf[:n])

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

// tunWriter writes packets from receive queue to TUN device
func (t *Tunnel) tunWriter() {
	defer t.wg.Done()
	
	for {
		select {
		case <-t.stopCh:
			return
		case packet := <-t.recvQueue:
			if _, err := t.tunFile.Write(packet); err != nil {
				if !isClosed(t.stopCh) {
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
			if !isClosed(t.stopCh) {
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
				if !isClosed(t.stopCh) {
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
				if !isClosed(t.stopCh) {
					log.Printf("Keepalive error: %v", err)
				}
				return
			}
		}
	}
}

// isClosed checks if a channel is closed
func isClosed(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
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
