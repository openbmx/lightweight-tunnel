package p2p

import (
	"net"
	"testing"
	"time"
)

func TestMonitorConnectionTimeoutFallsBackToServer(t *testing.T) {
	mgr := NewManager(0)
	mgr.SetHandshakeTimeout(20 * time.Millisecond)

	peerIP := net.ParseIP("10.0.0.2")
	peer := NewPeerInfo(peerIP)

	mgr.mu.Lock()
	mgr.peers[peerIP.String()] = peer
	mgr.mu.Unlock()

	done := make(chan struct{})
	go func() {
		mgr.monitorConnectionTimeout(peerIP.String())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("timeout monitor did not finish in expected window")
	}

	if clone := peer.Clone(); !clone.ThroughServer {
		t.Fatalf("expected peer to fall back to server after timeout")
	}
}
