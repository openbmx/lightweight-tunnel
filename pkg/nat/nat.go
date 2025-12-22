package nat

import (
	"fmt"
	"log"
	"net"
	"time"
)

// NATType represents different types of NAT
type NATType int

const (
	// NATUnknown means NAT type couldn't be determined
	NATUnknown NATType = iota
	// NATNone means no NAT (direct public IP)
	NATNone
	// NATFullCone means Full Cone NAT (most permissive)
	NATFullCone
	// NATRestrictedCone means Restricted Cone NAT (restricts by IP)
	NATRestrictedCone
	// NATPortRestrictedCone means Port-Restricted Cone NAT (restricts by IP:Port)
	NATPortRestrictedCone
	// NATSymmetric means Symmetric NAT (most restrictive, changes port per destination)
	NATSymmetric
)

// String returns the string representation of NAT type
func (n NATType) String() string {
	switch n {
	case NATNone:
		return "None (Public IP)"
	case NATFullCone:
		return "Full Cone"
	case NATRestrictedCone:
		return "Restricted Cone"
	case NATPortRestrictedCone:
		return "Port-Restricted Cone"
	case NATSymmetric:
		return "Symmetric"
	default:
		return "Unknown"
	}
}

// GetLevel returns the NAT level (0=best for P2P, higher=worse for P2P)
// Higher-level (worse) NAT should actively connect to lower-level (better) NAT
func (n NATType) GetLevel() int {
	switch n {
	case NATNone:
		return 0 // Best: Direct public IP
	case NATFullCone:
		return 1 // Very good: Any external host can connect
	case NATRestrictedCone:
		return 2 // Good: Restricted by IP only
	case NATPortRestrictedCone:
		return 3 // Moderate: Restricted by IP and port
	case NATSymmetric:
		return 4 // Worst: Changes port per destination
	default:
		return 5 // Unknown: Treat as worst case
	}
}

// CanTraverseWith checks if P2P is likely to succeed between two NAT types
func (n NATType) CanTraverseWith(other NATType) bool {
	// If either side has no NAT or full cone, P2P should work
	if n == NATNone || other == NATNone || n == NATFullCone || other == NATFullCone {
		return true
	}

	// Restricted cone can work with restricted or port-restricted cone
	if (n == NATRestrictedCone || n == NATPortRestrictedCone) &&
		(other == NATRestrictedCone || other == NATPortRestrictedCone) {
		return true
	}

	// Symmetric NAT with symmetric NAT is very difficult
	if n == NATSymmetric && other == NATSymmetric {
		return false
	}

	// One symmetric NAT with cone NAT has low success rate but possible
	if n == NATSymmetric || other == NATSymmetric {
		return true // Attempt but with low expectations
	}

	return false
}

// ShouldInitiateConnection determines if this NAT should initiate connection to the other
// Prefer better (lower level) NAT to initiate, improving success rate and reducing latency
// Nodes with permissive NATs can usually reach restrictive peers more reliably during hole punching.
func (n NATType) ShouldInitiateConnection(other NATType) bool {
	// Prefer the side with better NAT characteristics to initiate to reduce latency and failures
	return n.GetLevel() < other.GetLevel()
}

// Detector handles NAT type detection
type Detector struct {
	testPort    int
	testTimeout time.Duration
}

// NewDetector creates a new NAT type detector
func NewDetector(testPort int, timeout time.Duration) *Detector {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	return &Detector{
		testPort:    testPort,
		testTimeout: timeout,
	}
}

// DetectNATType attempts to detect the NAT type
// Uses STUN protocol (RFC 5389) for reliable detection when possible
func (d *Detector) DetectNATType(serverAddr string) (NATType, error) {
	// Step 1: Try STUN-based detection first (most reliable)
	if serverAddr != "" {
		natType, err := d.detectWithSTUN(serverAddr)
		if err != nil {
			log.Printf("STUN detection failed, falling back to simple detection: %v", err)
		} else {
			log.Printf("STUN-based NAT detection successful: %s", natType)
			return natType, nil
		}
	}

	// Step 2: Fallback to local detection if STUN unavailable
	// Try to detect if we have a public IP (no NAT)
	hasPublicIP, err := d.hasPublicIP()
	if err != nil {
		log.Printf("Failed to check for public IP: %v", err)
	} else if hasPublicIP {
		log.Println("Detected public IP - no NAT present")
		return NATNone, nil
	}

	// Step 3: Test for symmetric NAT by checking if port changes per destination
	isSymmetric, err := d.testSymmetricNAT(serverAddr)
	if err != nil {
		log.Printf("Failed to test for symmetric NAT: %v", err)
		// Continue with other tests
	} else if isSymmetric {
		log.Println("Detected Symmetric NAT (local test)")
		return NATSymmetric, nil
	}

	// Step 4: If not symmetric, it's some type of cone NAT
	// Without external STUN servers, we'll default to Port-Restricted Cone
	// which is the most common type and a safe middle ground
	log.Println("Detected Cone NAT (likely Port-Restricted)")
	return NATPortRestrictedCone, nil
}

// detectWithSTUN performs NAT detection using STUN protocol
func (d *Detector) detectWithSTUN(serverAddr string) (NATType, error) {
	// Try multiple STUN servers for better reliability
	// Includes servers accessible from China and other restricted regions
	stunServers := []string{
		serverAddr, // User-configured server (if provided)
		// Google STUN servers (may be blocked in some regions)
		"stun.l.google.com:19302",
		"stun1.l.google.com:19302",
		"stun2.l.google.com:19302",
		// Cloudflare STUN server (globally accessible)
		"stun.cloudflare.com:3478",
		// Twilio STUN servers (reliable and globally accessible)
		"stun.twilio.com:3478",
		// Xirsys STUN servers (good for Asia-Pacific region)
		"stun.stunprotocol.org:3478",
		// Additional public STUN servers for redundancy
		"stun.ekiga.net:3478",
		"stun.ideasip.com:3478",
		// China-accessible alternatives
		"stun.sipgate.net:3478",
		"stun.voip.eutelia.it:3478",
	}

	// Use the same port for STUN queries as P2P connections
	// This ensures NAT type detection reflects actual P2P behavior
	localAddr := &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: d.testPort,
	}

	var lastErr error
	for _, server := range stunServers {
		client := NewSTUNClient(server, d.testTimeout)
		natType, err := client.DetectNATTypeWithSTUN(localAddr)
		if err == nil {
			log.Printf("Successfully detected NAT type using STUN server %s on local port %d: %s", 
				server, d.testPort, natType)
			return natType, nil
		}
		lastErr = err
		log.Printf("STUN detection failed with server %s: %v", server, err)
	}

	return NATUnknown, fmt.Errorf("all STUN servers failed, last error: %v", lastErr)
}

// hasPublicIP checks if the local address is a public IP
func (d *Detector) hasPublicIP() (bool, error) {
	// Get the first non-loopback network interface
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false, err
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				// Check if it's a public IP
				if !isPrivateIP(ipnet.IP) {
					return true, nil
				}
			}
		}
	}

	return false, nil
}

// isPrivateIP checks if an IP is in private IP ranges
func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	// Check RFC 1918 private IP ranges
	privateRanges := []struct {
		start net.IP
		end   net.IP
	}{
		{net.ParseIP("10.0.0.0"), net.ParseIP("10.255.255.255")},
		{net.ParseIP("172.16.0.0"), net.ParseIP("172.31.255.255")},
		{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.255.255")},
	}

	for _, r := range privateRanges {
		if bytesInRange(ip.To4(), r.start.To4(), r.end.To4()) {
			return true
		}
	}

	return false
}

// bytesInRange checks if ip is between start and end (inclusive)
func bytesInRange(ip, start, end net.IP) bool {
	if len(ip) != len(start) || len(ip) != len(end) {
		return false
	}

	// Single pass comparison: check both bounds simultaneously
	for i := range ip {
		// If IP byte is less than start byte at this position, IP < start
		if ip[i] < start[i] {
			return false
		}
		// If IP byte is greater than start byte, IP is definitely >= start
		// Now only need to check upper bound
		if ip[i] > start[i] {
			// Check remaining bytes against end
			for j := i; j < len(ip); j++ {
				if ip[j] > end[j] {
					return false
				}
				if ip[j] < end[j] {
					return true
				}
			}
			return true // IP == end for remaining bytes
		}
		// If ip[i] == start[i], continue checking next byte
	}
	
	// All bytes equal to start, so IP == start. Now verify IP <= end
	for i := range ip {
		if ip[i] > end[i] {
			return false
		}
		if ip[i] < end[i] {
			return true
		}
	}
	return true // IP == start == end
}

// testSymmetricNAT tests if the NAT is symmetric by checking port binding behavior
func (d *Detector) testSymmetricNAT(serverAddr string) (bool, error) {
	// For a simplified test, we'll check if we can reuse the same local port
	// Symmetric NATs typically allocate different ports for different destinations

	// Create first connection
	conn1, err := net.Dial("udp4", serverAddr)
	if err != nil {
		return false, fmt.Errorf("failed to create first test connection: %v", err)
	}
	defer conn1.Close()

	localAddr1 := conn1.LocalAddr().(*net.UDPAddr)

	// Try to bind to the same local address for a different destination
	// If successful, it's likely not symmetric NAT
	localAddrStr := fmt.Sprintf(":%d", localAddr1.Port)
	testAddr, err := net.ResolveUDPAddr("udp4", localAddrStr)
	if err != nil {
		return false, err
	}

	testConn, err := net.ListenUDP("udp4", testAddr)
	if err != nil {
		// If we can't bind to the same port, might indicate symmetric behavior
		// This suggests the NAT is holding the port mapping exclusively
		return true, nil // Likely symmetric
	}
	testConn.Close()

	// If we successfully bound to the same port, likely non-symmetric
	return false, nil
}

// DetectNATTypeSimple performs a simple NAT type detection without external servers
// This is used as a fallback when server-based detection isn't available
func (d *Detector) DetectNATTypeSimple() NATType {
	// Check for public IP
	hasPublic, err := d.hasPublicIP()
	if err == nil && hasPublic {
		return NATNone
	}

	// Without external STUN servers, we default to Port-Restricted Cone
	// This is a reasonable middle-ground assumption
	log.Println("Using simple NAT detection: assuming Port-Restricted Cone NAT")
	return NATPortRestrictedCone
}
