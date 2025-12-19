package p2p

import (
	"net"
	"testing"
	"time"
)

func TestNewPeerInfo(t *testing.T) {
	ip := net.ParseIP("10.0.0.2")
	peer := NewPeerInfo(ip)

	if peer == nil {
		t.Fatal("NewPeerInfo returned nil")
	}

	if !peer.TunnelIP.Equal(ip) {
		t.Errorf("Expected tunnel IP %s, got %s", ip, peer.TunnelIP)
	}

	if peer.RelayPeers == nil {
		t.Error("RelayPeers should be initialized")
	}

	if len(peer.RelayPeers) != 0 {
		t.Error("RelayPeers should be empty initially")
	}

	if peer.NATType != NATUnknown {
		t.Errorf("Expected default NAT type %s, got %s", NATUnknown, peer.NATType)
	}
}

func TestPeerInfo_UpdateLatency(t *testing.T) {
	peer := NewPeerInfo(net.ParseIP("10.0.0.2"))

	latency := 10 * time.Millisecond
	peer.UpdateLatency(latency)

	peer.mu.RLock()
	if peer.Latency != latency {
		t.Errorf("Expected latency %v, got %v", latency, peer.Latency)
	}
	peer.mu.RUnlock()
}

func TestPeerInfo_UpdatePacketLoss(t *testing.T) {
	peer := NewPeerInfo(net.ParseIP("10.0.0.2"))

	loss := 0.05 // 5% packet loss
	peer.UpdatePacketLoss(loss)

	peer.mu.RLock()
	if peer.PacketLoss != loss {
		t.Errorf("Expected packet loss %f, got %f", loss, peer.PacketLoss)
	}
	peer.mu.RUnlock()
}

func TestPeerInfo_SetConnected(t *testing.T) {
	peer := NewPeerInfo(net.ParseIP("10.0.0.2"))

	peer.SetConnected(true)

	peer.mu.RLock()
	if !peer.Connected {
		t.Error("Peer should be connected")
	}
	if peer.ThroughServer {
		t.Error("ThroughServer should be false when connected")
	}
	peer.mu.RUnlock()
}

func TestPeerInfo_SetLocalConnection(t *testing.T) {
	peer := NewPeerInfo(net.ParseIP("10.0.0.2"))

	peer.SetLocalConnection(true)

	peer.mu.RLock()
	if !peer.IsLocalConnection {
		t.Error("Peer should be marked as local connection")
	}
	peer.mu.RUnlock()

	peer.SetLocalConnection(false)

	peer.mu.RLock()
	if peer.IsLocalConnection {
		t.Error("Peer should not be marked as local connection")
	}
	peer.mu.RUnlock()

	peer.SetNATType(NATSymmetric)
	if got := peer.GetNATType(); got != NATSymmetric {
		t.Errorf("expected NAT type %s, got %s", NATSymmetric, got)
	}
}

func TestPeerInfo_GetQualityScore(t *testing.T) {
	tests := []struct {
		name          string
		latency       time.Duration
		packetLoss    float64
		connected     bool
		throughServer bool
		isLocalConn   bool
		expectedMin   int
		expectedMax   int
	}{
		{
			name:        "Perfect connection",
			latency:     1 * time.Millisecond,
			packetLoss:  0.0,
			connected:   true,
			expectedMin: 100,
			expectedMax: 120,
		},
		{
			name:        "Good P2P connection",
			latency:     10 * time.Millisecond,
			packetLoss:  0.01,
			connected:   true,
			expectedMin: 95,
			expectedMax: 110,
		},
		{
			name:          "Server connection with latency",
			latency:       50 * time.Millisecond,
			packetLoss:    0.02,
			connected:     false,
			throughServer: true,
			expectedMin:   0,
			expectedMax:   50,
		},
		{
			name:        "Poor connection",
			latency:     100 * time.Millisecond,
			packetLoss:  0.1,
			connected:   false,
			expectedMin: 0,
			expectedMax: 20,
		},
		{
			name:        "Local network connection (highest priority)",
			latency:     1 * time.Millisecond,
			packetLoss:  0.0,
			connected:   true,
			isLocalConn: true,
			expectedMin: 130, // 100 base + 20 P2P bonus + 30 local bonus
			expectedMax: 150,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peer := NewPeerInfo(net.ParseIP("10.0.0.2"))
			peer.UpdateLatency(tt.latency)
			peer.UpdatePacketLoss(tt.packetLoss)
			peer.SetConnected(tt.connected)
			if tt.throughServer {
				peer.SetThroughServer(true)
			}
			if tt.isLocalConn {
				peer.SetLocalConnection(true)
			}

			score := peer.GetQualityScore()

			if score < tt.expectedMin || score > tt.expectedMax {
				t.Errorf("Quality score %d not in expected range [%d, %d]",
					score, tt.expectedMin, tt.expectedMax)
			}
		})
	}
}

func TestPeerInfo_AddRelayPeer(t *testing.T) {
	peer := NewPeerInfo(net.ParseIP("10.0.0.2"))

	relay1 := net.ParseIP("10.0.0.3")
	relay2 := net.ParseIP("10.0.0.4")

	peer.AddRelayPeer(relay1)
	peer.AddRelayPeer(relay2)

	peer.mu.RLock()
	if len(peer.RelayPeers) != 2 {
		t.Errorf("Expected 2 relay peers, got %d", len(peer.RelayPeers))
	}
	peer.mu.RUnlock()

	// Adding the same peer again should not duplicate
	peer.AddRelayPeer(relay1)

	peer.mu.RLock()
	if len(peer.RelayPeers) != 2 {
		t.Errorf("Expected 2 relay peers after duplicate add, got %d", len(peer.RelayPeers))
	}
	peer.mu.RUnlock()
}

func TestPeerInfo_IsStale(t *testing.T) {
	peer := NewPeerInfo(net.ParseIP("10.0.0.2"))

	// Peer should not be stale immediately
	if peer.IsStale(1 * time.Second) {
		t.Error("Peer should not be stale immediately after creation")
	}

	// Update last seen to old time
	peer.mu.Lock()
	peer.LastSeen = time.Now().Add(-2 * time.Minute)
	peer.mu.Unlock()

	// Peer should be stale now
	if !peer.IsStale(1 * time.Minute) {
		t.Error("Peer should be stale after timeout")
	}
}

func TestPeerInfo_Clone(t *testing.T) {
	original := NewPeerInfo(net.ParseIP("10.0.0.2"))
	original.PublicAddr = "1.2.3.4:10000"
	original.LocalAddr = "192.168.1.10:10000"
	original.UpdateLatency(10 * time.Millisecond)
	original.UpdatePacketLoss(0.05)
	original.SetConnected(true)
	original.SetNATType(NATSymmetric)
	original.AddRelayPeer(net.ParseIP("10.0.0.3"))

	clone := original.Clone()

	if clone == nil {
		t.Fatal("Clone returned nil")
	}

	if !clone.TunnelIP.Equal(original.TunnelIP) {
		t.Error("Cloned TunnelIP does not match")
	}

	if clone.PublicAddr != original.PublicAddr {
		t.Error("Cloned PublicAddr does not match")
	}

	if clone.LocalAddr != original.LocalAddr {
		t.Error("Cloned LocalAddr does not match")
	}

	if clone.NATType != original.NATType {
		t.Error("Cloned NATType does not match")
	}

	if clone.Latency != original.Latency {
		t.Error("Cloned Latency does not match")
	}

	if clone.PacketLoss != original.PacketLoss {
		t.Error("Cloned PacketLoss does not match")
	}

	if clone.Connected != original.Connected {
		t.Error("Cloned Connected does not match")
	}

	if len(clone.RelayPeers) != len(original.RelayPeers) {
		t.Error("Cloned RelayPeers length does not match")
	}
}
