package routing

import (
	"net"
	"testing"
	"time"

	"github.com/C018/lightweight-tunnel/pkg/p2p"
)

func TestNewRoutingTable(t *testing.T) {
	rt := NewRoutingTable(3)
	
	if rt == nil {
		t.Fatal("NewRoutingTable returned nil")
	}
	
	if rt.maxHops != 3 {
		t.Errorf("Expected maxHops 3, got %d", rt.maxHops)
	}
	
	if rt.routes == nil {
		t.Error("routes map should be initialized")
	}
	
	if rt.peers == nil {
		t.Error("peers map should be initialized")
	}
}

func TestRoutingTable_AddPeer(t *testing.T) {
	rt := NewRoutingTable(3)
	
	peer := p2p.NewPeerInfo(net.ParseIP("10.0.0.2"))
	peer.SetConnected(true)
	
	rt.AddPeer(peer)
	
	// Check if peer was added
	retrievedPeer := rt.GetPeer(peer.TunnelIP)
	if retrievedPeer == nil {
		t.Fatal("Peer was not added to routing table")
	}
	
	if !retrievedPeer.TunnelIP.Equal(peer.TunnelIP) {
		t.Error("Retrieved peer does not match added peer")
	}
	
	// Check if route was created
	route := rt.GetRoute(peer.TunnelIP)
	if route == nil {
		t.Fatal("Route was not created for peer")
	}
	
	if route.Type != RouteDirect {
		t.Errorf("Expected direct route, got type %d", route.Type)
	}
}

func TestRoutingTable_GetRoute(t *testing.T) {
	rt := NewRoutingTable(3)
	
	// Add a connected peer (should create direct route)
	peer1 := p2p.NewPeerInfo(net.ParseIP("10.0.0.2"))
	peer1.SetConnected(true)
	rt.AddPeer(peer1)
	
	route := rt.GetRoute(peer1.TunnelIP)
	if route == nil {
		t.Fatal("Route not found")
	}
	
	if route.Type != RouteDirect {
		t.Errorf("Expected direct route, got type %d", route.Type)
	}
	
	if route.Hops != 1 {
		t.Errorf("Expected 1 hop, got %d", route.Hops)
	}
}

func TestRoutingTable_RouteSelection(t *testing.T) {
	tests := []struct {
		name         string
		setupPeer    func() *p2p.PeerInfo
		expectedType RouteType
	}{
		{
			name: "Direct P2P connection",
			setupPeer: func() *p2p.PeerInfo {
				peer := p2p.NewPeerInfo(net.ParseIP("10.0.0.2"))
				peer.SetConnected(true)
				peer.UpdateLatency(5 * time.Millisecond)
				return peer
			},
			expectedType: RouteDirect,
		},
		{
			name: "Server route",
			setupPeer: func() *p2p.PeerInfo {
				peer := p2p.NewPeerInfo(net.ParseIP("10.0.0.3"))
				peer.SetConnected(false)
				peer.SetThroughServer(true)
				return peer
			},
			expectedType: RouteServer,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := NewRoutingTable(3)
			peer := tt.setupPeer()
			rt.AddPeer(peer)
			
			route := rt.GetRoute(peer.TunnelIP)
			if route == nil {
				t.Fatal("Route not found")
			}
			
			if route.Type != tt.expectedType {
				t.Errorf("Expected route type %d, got %d", tt.expectedType, route.Type)
			}
		})
	}
}

func TestRoutingTable_UpdateRoutes(t *testing.T) {
	rt := NewRoutingTable(3)
	
	// Add a peer with initial state
	peer := p2p.NewPeerInfo(net.ParseIP("10.0.0.2"))
	peer.SetConnected(false)
	peer.SetThroughServer(true)
	rt.AddPeer(peer)
	
	// Check initial route
	route := rt.GetRoute(peer.TunnelIP)
	if route == nil {
		t.Fatal("Route not found")
	}
	if route.Type != RouteServer {
		t.Errorf("Expected server route initially, got type %d", route.Type)
	}
	
	// Change peer state to connected
	peer.SetConnected(true)
	peer.UpdateLatency(5 * time.Millisecond)
	
	// Update routes
	rt.UpdateRoutes()
	
	// Check updated route
	route = rt.GetRoute(peer.TunnelIP)
	if route == nil {
		t.Fatal("Route not found after update")
	}
	if route.Type != RouteDirect {
		t.Errorf("Expected direct route after update, got type %d", route.Type)
	}
}

func TestRoutingTable_RemovePeer(t *testing.T) {
	rt := NewRoutingTable(3)
	
	peer := p2p.NewPeerInfo(net.ParseIP("10.0.0.2"))
	rt.AddPeer(peer)
	
	// Verify peer was added
	if rt.GetPeer(peer.TunnelIP) == nil {
		t.Fatal("Peer was not added")
	}
	
	// Remove peer
	rt.RemovePeer(peer.TunnelIP)
	
	// Verify peer was removed
	if rt.GetPeer(peer.TunnelIP) != nil {
		t.Error("Peer was not removed")
	}
	
	// Verify route was removed
	if rt.GetRoute(peer.TunnelIP) != nil {
		t.Error("Route was not removed")
	}
}

func TestRoutingTable_GetAllPeers(t *testing.T) {
	rt := NewRoutingTable(3)
	
	peer1 := p2p.NewPeerInfo(net.ParseIP("10.0.0.2"))
	peer2 := p2p.NewPeerInfo(net.ParseIP("10.0.0.3"))
	peer3 := p2p.NewPeerInfo(net.ParseIP("10.0.0.4"))
	
	rt.AddPeer(peer1)
	rt.AddPeer(peer2)
	rt.AddPeer(peer3)
	
	allPeers := rt.GetAllPeers()
	
	if len(allPeers) != 3 {
		t.Errorf("Expected 3 peers, got %d", len(allPeers))
	}
}

func TestRoutingTable_CleanStaleRoutes(t *testing.T) {
	rt := NewRoutingTable(3)
	
	peer := p2p.NewPeerInfo(net.ParseIP("10.0.0.2"))
	peer.SetConnected(true)
	rt.AddPeer(peer)
	
	// Get the route and update its timestamp to be old
	rt.mu.Lock()
	if route, exists := rt.routes[peer.TunnelIP.String()]; exists {
		route.LastUpdated = time.Now().Add(-2 * time.Minute)
	}
	rt.mu.Unlock()
	
	// Clean stale routes (timeout 1 minute)
	rt.CleanStaleRoutes(1 * time.Minute)
	
	// Route should be removed
	route := rt.GetRoute(peer.TunnelIP)
	if route != nil {
		t.Error("Stale route was not cleaned")
	}
}

func TestRoutingTable_GetRouteStats(t *testing.T) {
	rt := NewRoutingTable(3)
	
	// Add peers with different connection types
	peer1 := p2p.NewPeerInfo(net.ParseIP("10.0.0.2"))
	peer1.SetConnected(true)
	rt.AddPeer(peer1)
	
	peer2 := p2p.NewPeerInfo(net.ParseIP("10.0.0.3"))
	peer2.SetConnected(true)
	rt.AddPeer(peer2)
	
	peer3 := p2p.NewPeerInfo(net.ParseIP("10.0.0.4"))
	peer3.SetConnected(false)
	peer3.SetThroughServer(true)
	rt.AddPeer(peer3)
	
	stats := rt.GetRouteStats()
	
	if stats["total_peers"] != 3 {
		t.Errorf("Expected 3 total peers, got %d", stats["total_peers"])
	}
	
	if stats["total_routes"] != 3 {
		t.Errorf("Expected 3 total routes, got %d", stats["total_routes"])
	}
	
	if stats["direct_routes"] != 2 {
		t.Errorf("Expected 2 direct routes, got %d", stats["direct_routes"])
	}
	
	if stats["server_routes"] != 1 {
		t.Errorf("Expected 1 server route, got %d", stats["server_routes"])
	}
}

func TestRoutingTable_QualityBasedSelection(t *testing.T) {
	rt := NewRoutingTable(3)
	
	// Create peer with low quality P2P (high latency, packet loss)
	peer := p2p.NewPeerInfo(net.ParseIP("10.0.0.2"))
	peer.SetConnected(true)
	peer.UpdateLatency(200 * time.Millisecond) // Very high latency
	peer.UpdatePacketLoss(0.3)                  // 30% packet loss
	
	rt.AddPeer(peer)
	
	route := rt.GetRoute(peer.TunnelIP)
	if route == nil {
		t.Fatal("Route not found")
	}
	
	// Even with poor quality, P2P should still be selected if it's the only option
	// The quality score should reflect the poor conditions
	if route.Quality > 50 {
		t.Errorf("Expected low quality score for poor connection, got %d", route.Quality)
	}
}

func TestRoutingTable_LocalConnectionPriority(t *testing.T) {
	rt := NewRoutingTable(3)
	
	// Create a peer with local connection (highest priority)
	localPeer := p2p.NewPeerInfo(net.ParseIP("10.0.0.2"))
	localPeer.SetConnected(true)
	localPeer.SetLocalConnection(true) // Local network connection
	localPeer.UpdateLatency(5 * time.Millisecond)
	
	// Create a peer with public connection
	publicPeer := p2p.NewPeerInfo(net.ParseIP("10.0.0.3"))
	publicPeer.SetConnected(true)
	publicPeer.SetLocalConnection(false) // Public NAT traversal
	publicPeer.UpdateLatency(5 * time.Millisecond)
	
	rt.AddPeer(localPeer)
	rt.AddPeer(publicPeer)
	
	localRoute := rt.GetRoute(localPeer.TunnelIP)
	publicRoute := rt.GetRoute(publicPeer.TunnelIP)
	
	if localRoute == nil || publicRoute == nil {
		t.Fatal("Routes not found")
	}
	
	// Local connection should have higher quality score
	if localRoute.Quality <= publicRoute.Quality {
		t.Errorf("Local connection should have higher quality score. Local: %d, Public: %d",
			localRoute.Quality, publicRoute.Quality)
	}
	
	// Both should be direct routes
	if localRoute.Type != RouteDirect {
		t.Errorf("Expected local route to be direct, got %d", localRoute.Type)
	}
	if publicRoute.Type != RouteDirect {
		t.Errorf("Expected public route to be direct, got %d", publicRoute.Type)
	}
}
