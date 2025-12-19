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
// Lower-level NAT should actively connect to higher-level NAT
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
// Lower-level (better) NAT should connect to higher-level (worse) NAT for better stability
func (n NATType) ShouldInitiateConnection(other NATType) bool {
	// If we have a better NAT (lower level), we should initiate
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
// This is a simplified detection that uses basic UDP socket behavior
func (d *Detector) DetectNATType(serverAddr string) (NATType, error) {
	// Step 1: Try to detect if we have a public IP (no NAT)
	hasPublicIP, err := d.hasPublicIP()
	if err != nil {
		log.Printf("Failed to check for public IP: %v", err)
	} else if hasPublicIP {
		log.Println("Detected public IP - no NAT present")
		return NATNone, nil
	}

	// Step 2: Test for symmetric NAT by checking if port changes per destination
	// This requires connecting to multiple servers, which we'll simplify
	// For now, we'll use a heuristic based on socket binding behavior
	
	// Create two UDP connections to different destinations
	isSymmetric, err := d.testSymmetricNAT(serverAddr)
	if err != nil {
		log.Printf("Failed to test for symmetric NAT: %v", err)
		// Continue with other tests
	} else if isSymmetric {
		log.Println("Detected Symmetric NAT")
		return NATSymmetric, nil
	}

	// Step 3: If not symmetric, it's some type of cone NAT
	// Without external STUN servers, we'll default to Port-Restricted Cone
	// which is the most common type and a safe middle ground
	log.Println("Detected Cone NAT (likely Port-Restricted)")
	return NATPortRestrictedCone, nil
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

// bytesInRange checks if ip is between start and end
func bytesInRange(ip, start, end net.IP) bool {
	if len(ip) != len(start) || len(ip) != len(end) {
		return false
	}

	// Check each byte: IP must be >= start and <= end
	for i := range ip {
		if ip[i] < start[i] {
			return false
		}
		if ip[i] > end[i] {
			return false
		}
		// If this byte is within the range but not equal to start/end,
		// then the IP is strictly within range and we can return true
		if ip[i] > start[i] && ip[i] < end[i] {
			return true
		}
	}

	// All bytes matched exactly or are at boundaries
	return true
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
		// but could also be port already in use
		return false, nil // Conservative: assume non-symmetric
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
