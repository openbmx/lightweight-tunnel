package routing

import (
	"net"
	"sync"
	"time"

	"github.com/openbmx/lightweight-tunnel/pkg/p2p"
)

// RouteType represents the type of route
type RouteType int

const (
	RouteDirect RouteType = iota // Direct P2P connection
	RouteRelay                   // Relay through another client
	RouteServer                  // Through server
)

// Route represents a path to a destination
type Route struct {
	Destination net.IP        // Destination peer IP
	Type        RouteType     // Type of route
	NextHop     net.IP        // Next hop IP (for relay routes)
	Hops        int           // Number of hops
	Quality     int           // Quality score (0-100)
	LastUpdated time.Time     // Last time this route was updated
}

// RoutingTable manages routes to all peers
type RoutingTable struct {
	routes   map[string]*Route // Key: destination IP string
	peers    map[string]*p2p.PeerInfo // Peer information
	mu       sync.RWMutex
	maxHops  int               // Maximum allowed hops
}

// NewRoutingTable creates a new routing table
func NewRoutingTable(maxHops int) *RoutingTable {
	return &RoutingTable{
		routes:  make(map[string]*Route),
		peers:   make(map[string]*p2p.PeerInfo),
		maxHops: maxHops,
	}
}

// AddPeer adds or updates peer information
func (rt *RoutingTable) AddPeer(peer *p2p.PeerInfo) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	
	ipStr := peer.TunnelIP.String()
	rt.peers[ipStr] = peer
	
	// Update route for this peer
	rt.updateRouteForPeer(peer)
}

// updateRouteForPeer updates the best route to a peer (must be called with lock held)
func (rt *RoutingTable) updateRouteForPeer(peer *p2p.PeerInfo) {
	ipStr := peer.TunnelIP.String()
	
	// Check if direct P2P is available
	if peer.Connected {
		rt.routes[ipStr] = &Route{
			Destination: peer.TunnelIP,
			Type:        RouteDirect,
			NextHop:     peer.TunnelIP,
			Hops:        1,
			Quality:     peer.GetQualityScore(),
			LastUpdated: time.Now(),
		}
		return
	}
	
	// Check for relay routes through other peers
	bestRelayRoute := rt.findBestRelayRoute(peer)
	
	// Check server route quality
	serverQuality := peer.GetQualityScore()
	if peer.ThroughServer {
		serverQuality -= 20 // Penalty for server routing
	}
	
	// Choose best route
	if bestRelayRoute != nil && bestRelayRoute.Quality > serverQuality {
		rt.routes[ipStr] = bestRelayRoute
	} else {
		rt.routes[ipStr] = &Route{
			Destination: peer.TunnelIP,
			Type:        RouteServer,
			NextHop:     nil, // Server doesn't have a next hop
			Hops:        1,
			Quality:     serverQuality,
			LastUpdated: time.Now(),
		}
	}
}

// findBestRelayRoute finds the best relay route to a peer (must be called with lock held)
func (rt *RoutingTable) findBestRelayRoute(peer *p2p.PeerInfo) *Route {
	var bestRoute *Route
	
	for _, relayIP := range peer.RelayPeers {
		relayPeer, exists := rt.peers[relayIP.String()]
		if !exists || !relayPeer.Connected {
			continue
		}
		
		// Calculate relay route quality
		// Quality is based on relay peer quality minus a hop penalty
		relayQuality := relayPeer.GetQualityScore() - 15 // Penalty for additional hop
		
		// Don't exceed max hops
		hops := 2
		if hops > rt.maxHops {
			continue
		}
		
		if bestRoute == nil || relayQuality > bestRoute.Quality {
			bestRoute = &Route{
				Destination: peer.TunnelIP,
				Type:        RouteRelay,
				NextHop:     relayIP,
				Hops:        hops,
				Quality:     relayQuality,
				LastUpdated: time.Now(),
			}
		}
	}
	
	return bestRoute
}

// GetRoute gets the best route to a destination
func (rt *RoutingTable) GetRoute(dst net.IP) *Route {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	
	route, exists := rt.routes[dst.String()]
	if !exists {
		return nil
	}
	
	return route
}

// GetPeer gets peer information
func (rt *RoutingTable) GetPeer(ip net.IP) *p2p.PeerInfo {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	
	return rt.peers[ip.String()]
}

// GetAllPeers returns all peer information
func (rt *RoutingTable) GetAllPeers() []*p2p.PeerInfo {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	
	peers := make([]*p2p.PeerInfo, 0, len(rt.peers))
	for _, peer := range rt.peers {
		peers = append(peers, peer.Clone())
	}
	
	return peers
}

// RemovePeer removes a peer from the routing table
func (rt *RoutingTable) RemovePeer(ip net.IP) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	
	ipStr := ip.String()
	delete(rt.peers, ipStr)
	delete(rt.routes, ipStr)
}

// UpdateRoutes recalculates all routes based on current peer states
func (rt *RoutingTable) UpdateRoutes() {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	
	for _, peer := range rt.peers {
		rt.updateRouteForPeer(peer)
	}
}

// CleanStaleRoutes removes routes that haven't been updated recently
func (rt *RoutingTable) CleanStaleRoutes(timeout time.Duration) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	
	now := time.Now()
	for ipStr, route := range rt.routes {
		if now.Sub(route.LastUpdated) > timeout {
			delete(rt.routes, ipStr)
		}
	}
}

// GetRouteStats returns statistics about the routing table
func (rt *RoutingTable) GetRouteStats() map[string]int {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	
	stats := map[string]int{
		"total_peers":   len(rt.peers),
		"total_routes":  len(rt.routes),
		"direct_routes": 0,
		"relay_routes":  0,
		"server_routes": 0,
	}
	
	for _, route := range rt.routes {
		switch route.Type {
		case RouteDirect:
			stats["direct_routes"]++
		case RouteRelay:
			stats["relay_routes"]++
		case RouteServer:
			stats["server_routes"]++
		}
	}
	
	return stats
}
