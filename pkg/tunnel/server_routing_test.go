package tunnel

import (
	"net"
	"testing"
)

// TestGetPeerIPDerivesServerAddress verifies that GetPeerIP correctly
// derives the peer's tunnel IP from a given tunnel address.
// In client mode, this peer IP is the server's IP address.
func TestGetPeerIPDerivesServerAddress(t *testing.T) {
	tests := []struct {
		name           string
		tunnelAddr     string
		expectedPeerIP string
		expectError    bool
		description    string
	}{
		{
			name:           "client .2 derives peer .1",
			tunnelAddr:     "10.0.0.2/24",
			expectedPeerIP: "10.0.0.1",
			expectError:    false,
			description:    "When client is .2, peer (server) is .1",
		},
		{
			name:           "client .1 derives peer .2",
			tunnelAddr:     "10.0.0.1/24",
			expectedPeerIP: "10.0.0.2",
			expectError:    false,
			description:    "When client is .1, peer (server) is .2",
		},
		{
			name:           "client .10 derives peer .1",
			tunnelAddr:     "10.0.0.10/24",
			expectedPeerIP: "10.0.0.1",
			expectError:    false,
			description:    "When client is .10, peer (server) is .1",
		},
		{
			name:           "client .100 derives peer .1",
			tunnelAddr:     "192.168.1.100/24",
			expectedPeerIP: "192.168.1.1",
			expectError:    false,
			description:    "When client is .100, peer (server) is .1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peerAddr, err := GetPeerIP(tt.tunnelAddr)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Extract IP from CIDR
			ip, _, err := net.ParseCIDR(peerAddr)
			if err != nil {
				t.Fatalf("Failed to parse returned address %s: %v", peerAddr, err)
			}

			expectedIP := net.ParseIP(tt.expectedPeerIP)
			if !ip.Equal(expectedIP) {
				t.Errorf("Expected peer IP to be %s, got %s", tt.expectedPeerIP, ip)
			}

			t.Logf("%s: Successfully derived peer IP %s from address %s", 
				tt.description, ip, tt.tunnelAddr)
		})
	}
}

// TestServerIPRoutingLogic documents the expected routing behavior
// This is a documentation test that describes the fix for the P2P request issue
func TestServerIPRoutingLogic(t *testing.T) {
	t.Log("=== Client-to-Server Routing Fix ===")
	t.Log("")
	t.Log("Problem: Client was sending P2P requests for server's tunnel IP")
	t.Log("  - Client tries to send packet to server (e.g., 10.0.0.1)")
	t.Log("  - sendPacketWithRouting() didn't recognize server IP")
	t.Log("  - Attempted to establish P2P with server")
	t.Log("  - Server logged: 'P2P request for unknown target 10.0.0.1, ignoring'")
	t.Log("")
	t.Log("Solution: Added serverTunnelIP field to Tunnel struct")
	t.Log("  1. In registerServerPeer(): Store server's tunnel IP during initialization")
	t.Log("  2. In sendPacketWithRouting(): Check if destination == serverTunnelIP")
	t.Log("  3. If yes: Send directly via server connection (bypass P2P logic)")
	t.Log("  4. If no: Use normal P2P/routing logic for client-to-client traffic")
	t.Log("")
	t.Log("Expected behavior after fix:")
	t.Log("  - Client -> Server: Always via tunnel connection (no P2P request)")
	t.Log("  - Client -> Client: Try P2P first, fallback to server relay")
	t.Log("  - No more 'P2P request for unknown target' errors for server IP")
}
