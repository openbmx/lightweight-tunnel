package p2p

import (
	"testing"
	"time"

	"github.com/openbmx/lightweight-tunnel/pkg/nat"
)

func TestConnectionStats(t *testing.T) {
	manager := NewManager(0)
	
	// Test initial state
	stats := manager.GetConnectionStats()
	if stats.TotalAttempts != 0 {
		t.Errorf("Expected TotalAttempts=0, got %d", stats.TotalAttempts)
	}
	
	// Test recording regular attempt
	manager.recordConnectionAttempt(false)
	stats = manager.GetConnectionStats()
	if stats.TotalAttempts != 1 {
		t.Errorf("Expected TotalAttempts=1, got %d", stats.TotalAttempts)
	}
	if stats.SymmetricNATAttempts != 0 {
		t.Errorf("Expected SymmetricNATAttempts=0, got %d", stats.SymmetricNATAttempts)
	}
	
	// Test recording symmetric NAT attempt
	manager.recordConnectionAttempt(true)
	stats = manager.GetConnectionStats()
	if stats.TotalAttempts != 2 {
		t.Errorf("Expected TotalAttempts=2, got %d", stats.TotalAttempts)
	}
	if stats.SymmetricNATAttempts != 1 {
		t.Errorf("Expected SymmetricNATAttempts=1, got %d", stats.SymmetricNATAttempts)
	}
	
	// Test recording success
	handshakeTime := 100 * time.Millisecond
	manager.recordConnectionSuccess(true, false, handshakeTime)
	stats = manager.GetConnectionStats()
	if stats.SuccessfulAttempts != 1 {
		t.Errorf("Expected SuccessfulAttempts=1, got %d", stats.SuccessfulAttempts)
	}
	if stats.LocalConnections != 1 {
		t.Errorf("Expected LocalConnections=1, got %d", stats.LocalConnections)
	}
	if stats.PublicConnections != 0 {
		t.Errorf("Expected PublicConnections=0, got %d", stats.PublicConnections)
	}
	if stats.AverageHandshakeTime != handshakeTime {
		t.Errorf("Expected AverageHandshakeTime=%v, got %v", handshakeTime, stats.AverageHandshakeTime)
	}
	
	// Test recording public connection
	manager.recordConnectionSuccess(false, false, 200*time.Millisecond)
	stats = manager.GetConnectionStats()
	if stats.SuccessfulAttempts != 2 {
		t.Errorf("Expected SuccessfulAttempts=2, got %d", stats.SuccessfulAttempts)
	}
	if stats.PublicConnections != 1 {
		t.Errorf("Expected PublicConnections=1, got %d", stats.PublicConnections)
	}
	
	// Test recording symmetric NAT success
	manager.recordConnectionSuccess(false, true, 300*time.Millisecond)
	stats = manager.GetConnectionStats()
	if stats.SymmetricNATSuccess != 1 {
		t.Errorf("Expected SymmetricNATSuccess=1, got %d", stats.SymmetricNATSuccess)
	}
	
	// Test recording failure
	manager.recordConnectionFailure()
	stats = manager.GetConnectionStats()
	if stats.FailedAttempts != 1 {
		t.Errorf("Expected FailedAttempts=1, got %d", stats.FailedAttempts)
	}
	
	// Test recording server relay
	manager.recordServerRelay()
	stats = manager.GetConnectionStats()
	if stats.ServerRelayFallbacks != 1 {
		t.Errorf("Expected ServerRelayFallbacks=1, got %d", stats.ServerRelayFallbacks)
	}
	
	// Test success rates
	successRate := manager.GetConnectionSuccessRate()
	expectedRate := 3.0 / 2.0 // 3 successes / 2 total attempts (we only recorded 2 attempts)
	if successRate != expectedRate {
		t.Errorf("Expected success rate=%.2f, got %.2f", expectedRate, successRate)
	}
	
	symSuccessRate := manager.GetSymmetricNATSuccessRate()
	expectedSymRate := 1.0 / 1.0 // 1 symmetric success / 1 symmetric attempt
	if symSuccessRate != expectedSymRate {
		t.Errorf("Expected symmetric success rate=%.2f, got %.2f", expectedSymRate, symSuccessRate)
	}
}

func TestNATTypeLevels(t *testing.T) {
	tests := []struct {
		natType  nat.NATType
		expected int
	}{
		{nat.NATNone, 0},
		{nat.NATFullCone, 1},
		{nat.NATRestrictedCone, 2},
		{nat.NATPortRestrictedCone, 3},
		{nat.NATSymmetric, 4},
		{nat.NATUnknown, 5},
	}
	
	for _, tt := range tests {
		level := tt.natType.GetLevel()
		if level != tt.expected {
			t.Errorf("NAT type %s: expected level %d, got %d", tt.natType, tt.expected, level)
		}
	}
}

func TestShouldInitiateConnection(t *testing.T) {
	tests := []struct {
		myNAT    nat.NATType
		peerNAT  nat.NATType
		expected bool
	}{
		{nat.NATNone, nat.NATSymmetric, true},           // Better NAT initiates
		{nat.NATSymmetric, nat.NATNone, false},          // Worse NAT doesn't initiate
		{nat.NATFullCone, nat.NATPortRestrictedCone, true}, // Better NAT initiates
		{nat.NATSymmetric, nat.NATSymmetric, false},     // Equal NAT, first one doesn't initiate
		{nat.NATRestrictedCone, nat.NATRestrictedCone, false}, // Equal NAT
	}
	
	for _, tt := range tests {
		result := tt.myNAT.ShouldInitiateConnection(tt.peerNAT)
		if result != tt.expected {
			t.Errorf("MyNAT=%s, PeerNAT=%s: expected %v, got %v", 
				tt.myNAT, tt.peerNAT, tt.expected, result)
		}
	}
}

func TestCanTraverseWith(t *testing.T) {
	tests := []struct {
		myNAT    nat.NATType
		peerNAT  nat.NATType
		expected bool
	}{
		{nat.NATNone, nat.NATSymmetric, true},              // Public IP can connect to anything
		{nat.NATFullCone, nat.NATSymmetric, true},          // Full Cone works with most
		{nat.NATRestrictedCone, nat.NATPortRestrictedCone, true}, // Cone types work together
		{nat.NATSymmetric, nat.NATSymmetric, false},        // Double symmetric is difficult
		{nat.NATSymmetric, nat.NATFullCone, true},          // Symmetric with cone may work
	}
	
	for _, tt := range tests {
		result := tt.myNAT.CanTraverseWith(tt.peerNAT)
		if result != tt.expected {
			t.Errorf("MyNAT=%s, PeerNAT=%s: expected %v, got %v", 
				tt.myNAT, tt.peerNAT, tt.expected, result)
		}
	}
}

func TestPeerInfoQualityScore(t *testing.T) {
	peer := NewPeerInfo(nil)
	
	// Test base score
	score := peer.GetQualityScore()
	if score != 100 {
		t.Errorf("Expected base score=100, got %d", score)
	}
	
	// Test with P2P connection
	peer.SetConnected(true)
	score = peer.GetQualityScore()
	if score != 120 { // 100 base + 20 P2P bonus
		t.Errorf("Expected score with P2P=120, got %d", score)
	}
	
	// Test with local connection
	peer.SetLocalConnection(true)
	score = peer.GetQualityScore()
	if score != 150 { // 100 base + 20 P2P + 30 local bonus
		t.Errorf("Expected score with local=150, got %d", score)
	}
	
	// Test with server relay
	peer.SetThroughServer(true)
	score = peer.GetQualityScore()
	if score <= 100 { // Should have server penalty
		t.Errorf("Expected score with server relay penalty, got %d", score)
	}
	
	// Test with latency
	peer.UpdateLatency(50 * time.Millisecond)
	score = peer.GetQualityScore()
	// Score should be reduced by latency penalty
	// Latency of 50ms = 5 * 5 penalty = 25 points
	expectedMin := 150 - 30 - 25 // base + bonuses - server penalty - latency penalty
	if score > 150 || score < expectedMin-10 { // Allow some tolerance
		t.Errorf("Expected score with latency around %d, got %d", expectedMin, score)
	}
}

func TestConnectionStatsThreadSafety(t *testing.T) {
	manager := NewManager(0)
	
	// Concurrent writes
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				manager.recordConnectionAttempt(false)
				manager.recordConnectionSuccess(false, false, 100*time.Millisecond)
				manager.recordConnectionFailure()
				manager.recordServerRelay()
			}
			done <- true
		}()
	}
	
	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
	
	// Verify stats are consistent
	stats := manager.GetConnectionStats()
	if stats.TotalAttempts != 1000 {
		t.Errorf("Expected TotalAttempts=1000, got %d", stats.TotalAttempts)
	}
	if stats.SuccessfulAttempts != 1000 {
		t.Errorf("Expected SuccessfulAttempts=1000, got %d", stats.SuccessfulAttempts)
	}
	if stats.FailedAttempts != 1000 {
		t.Errorf("Expected FailedAttempts=1000, got %d", stats.FailedAttempts)
	}
	if stats.ServerRelayFallbacks != 1000 {
		t.Errorf("Expected ServerRelayFallbacks=1000, got %d", stats.ServerRelayFallbacks)
	}
}
