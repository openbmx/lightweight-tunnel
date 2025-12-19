package tunnel

import (
	"net"
	"testing"
	"time"

	"github.com/openbmx/lightweight-tunnel/internal/config"
	"github.com/openbmx/lightweight-tunnel/pkg/crypto"
)

type mockConn struct {
	writes [][]byte
	closed bool
}

func (m *mockConn) WritePacket(data []byte) error {
	m.writes = append(m.writes, append([]byte(nil), data...))
	return nil
}

func (m *mockConn) ReadPacket() ([]byte, error) { return nil, nil }

func (m *mockConn) Close() error {
	m.closed = true
	return nil
}

func (m *mockConn) LocalAddr() net.Addr  { return mockAddr("local") }
func (m *mockConn) RemoteAddr() net.Addr { return mockAddr("remote") }

func (m *mockConn) SetDeadline(time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(time.Time) error { return nil }

type mockAddr string

func (a mockAddr) Network() string { return "mock" }
func (a mockAddr) String() string  { return string(a) }

func TestPushConfigUpdateUsesAllClients(t *testing.T) {
	cfg := &config.Config{
		Mode:       "server",
		TunnelAddr: "10.0.0.1/24",
		Key:        "initial-key",
		Routes:     []string{"100.64.0.0/10"},
	}

	ciph, err := crypto.NewCipher(cfg.Key)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}
	originalCipher := ciph

	tun := &Tunnel{
		config:       cfg,
		cipher:       ciph,
		stopCh:       make(chan struct{}),
		clients:      make(map[string]*ClientConnection),
		clientRoutes: make(map[*ClientConnection][]string),
		allClients:   make(map[*ClientConnection]struct{}),
	}

	client := &ClientConnection{
		conn:   &mockConn{},
		stopCh: make(chan struct{}),
	}

	tun.trackClientConnection(client)

	if err := tun.pushConfigUpdate(); err != nil {
		t.Fatalf("pushConfigUpdate returned error: %v", err)
	}

	mock := client.conn.(*mockConn)
	if len(mock.writes) != 1 {
		t.Fatalf("expected config update to be sent, got %d writes", len(mock.writes))
	}

	if tun.config.Key == "initial-key" {
		t.Fatalf("expected key to rotate from initial value")
	}

	if tun.cipher == originalCipher {
		t.Fatalf("expected cipher to be replaced after rotation")
	}

	select {
	case <-client.stopCh:
	default:
		t.Fatalf("expected client stop channel to be closed")
	}

	if !mock.closed {
		t.Fatalf("expected client connection to be closed")
	}
}

func TestKeyRotationGraceAndInvalidation(t *testing.T) {
	cfg := &config.Config{
		Mode:       "server",
		TunnelAddr: "10.0.0.1/24",
		Key:        "old-key",
	}

	oldCipher, err := crypto.NewCipher(cfg.Key)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	tun := &Tunnel{
		config:       cfg,
		cipher:       oldCipher,
		stopCh:       make(chan struct{}),
		clients:      make(map[string]*ClientConnection),
		clientRoutes: make(map[*ClientConnection][]string),
		allClients:   make(map[*ClientConnection]struct{}),
	}
	tun.cipherGen = 1

	client := &ClientConnection{
		conn:   &mockConn{},
		stopCh: make(chan struct{}),
	}
	client.setCipherWithGen(oldCipher, tun.cipherGen)
	tun.trackClientConnection(client)

	if err := tun.rotateCipher("new-key-rotation"); err != nil {
		t.Fatalf("rotateCipher failed: %v", err)
	}

	if tun.prevCipher != oldCipher {
		t.Fatalf("expected previous cipher to be retained for grace period")
	}

	packet := []byte{PacketTypeKeepalive}
	encryptedOld, err := oldCipher.Encrypt(packet)
	if err != nil {
		t.Fatalf("encrypt with old cipher failed: %v", err)
	}

	if _, used, gen, err := tun.decryptPacketForServer(encryptedOld); err != nil || used != oldCipher || gen != tun.prevCipherGen {
		t.Fatalf("expected decrypt to succeed with old cipher during grace, used=%v gen=%d err=%v", used, gen, err)
	}

	select {
	case <-client.stopCh:
		t.Fatalf("client using old key should remain connected during grace period")
	default:
	}

	newCipher := tun.cipher
	encryptedNew, err := newCipher.Encrypt(packet)
	if err != nil {
		t.Fatalf("encrypt with new cipher failed: %v", err)
	}

	if _, used, gen, err := tun.decryptPacketForServer(encryptedNew); err != nil || used != newCipher || gen != tun.cipherGen {
		t.Fatalf("expected decrypt to use new cipher, used=%v gen=%d err=%v", used, gen, err)
	}

	if tun.prevCipher != nil {
		t.Fatalf("expected previous cipher to be cleared once new key is in use")
	}

	select {
	case <-client.stopCh:
	default:
		t.Fatalf("expected client with old key to be disconnected after new key is active")
	}

	if _, _, _, err := tun.decryptPacketForServer(encryptedOld); err == nil {
		t.Fatalf("expected old cipher to be invalid after new key confirmed")
	}
}
