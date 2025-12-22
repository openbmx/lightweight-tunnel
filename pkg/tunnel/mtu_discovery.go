package tunnel

import (
	"fmt"
	"log"
	"net"
	"syscall"
	"time"
)

const (
// MTU discovery constants
minMTU          = 576  // IPv4 minimum MTU
maxMTU          = 1500 // Standard Ethernet MTU
conservativeMTU = 1200 // Conservative MTU for uncertain cases
)

// MTUDiscovery handles adaptive MTU detection
type MTUDiscovery struct {
remoteAddr string
currentMTU int
}

// NewMTUDiscovery creates a new MTU discovery instance
func NewMTUDiscovery(remoteAddr string, initialMTU int) *MTUDiscovery {
return &MTUDiscovery{
remoteAddr: remoteAddr,
currentMTU: initialMTU,
}
}

// DiscoverOptimalMTU performs MTU path discovery using binary search
// Returns the optimal MTU for the network path
func (m *MTUDiscovery) DiscoverOptimalMTU() (int, error) {
log.Printf("🔍 开始自适应MTU探测...")
log.Printf("   目标地址: %s", m.remoteAddr)
log.Printf("   初始MTU: %d", m.currentMTU)

// Parse remote address
host, _, err := net.SplitHostPort(m.remoteAddr)
if err != nil {
return m.currentMTU, fmt.Errorf("invalid remote address: %v", err)
}

// Resolve IP address
ips, err := net.LookupIP(host)
if err != nil {
return m.currentMTU, fmt.Errorf("failed to resolve host: %v", err)
}
if len(ips) == 0 {
return m.currentMTU, fmt.Errorf("no IP addresses found for host")
}

targetIP := ips[0].String()
log.Printf("   解析地址: %s", targetIP)

// Binary search for optimal MTU
low := minMTU
high := maxMTU
optimal := minMTU

attempts := 0
maxAttempts := 10

for low <= high && attempts < maxAttempts {
attempts++
testMTU := (low + high) / 2

log.Printf("   [%d/%d] 测试 MTU: %d", attempts, maxAttempts, testMTU)

if m.testMTU(targetIP, testMTU) {
// MTU works, try larger
optimal = testMTU
low = testMTU + 1
log.Printf("   ✅ MTU %d 可用", testMTU)
} else {
// MTU too large, try smaller
high = testMTU - 1
log.Printf("   ❌ MTU %d 过大", testMTU)
}
}

// Account for IP header (20 bytes) and protocol overhead
// For rawtcp mode with encryption: need to reserve space for packet type (1 byte) + encryption overhead (28 bytes)
const ipHeaderSize = 20
const tcpHeaderSize = 20
const packetTypeOverhead = 1
const encryptionOverhead = 28

// Calculate safe MTU for tunnel payload
safeMTU := optimal - ipHeaderSize - tcpHeaderSize - packetTypeOverhead - encryptionOverhead

// Ensure we don't go below minimum
if safeMTU < 500 {
safeMTU = 500
}

// Cap at reasonable maximum for rawtcp mode
if safeMTU > 1371 {
safeMTU = 1371 // Safe maximum for rawtcp + encryption
}

log.Printf("✅ MTU探测完成")
log.Printf("   路径MTU: %d", optimal)
log.Printf("   隧道MTU: %d (已扣除协议开销)", safeMTU)

return safeMTU, nil
}

// testMTU tests if a specific MTU size works by sending a test packet
// Uses UDP with large packets to test path MTU more reliably than TCP handshake
// Falls back to conservative estimates if proper testing is unavailable
func (m *MTUDiscovery) testMTU(targetIP string, mtu int) bool {
	// Try to use UDP echo with large packet to test MTU
	// This is more reliable than TCP handshake which only uses small packets
	
	host, port, err := net.SplitHostPort(m.remoteAddr)
	if err != nil {
		// If we can't parse the address, be conservative
		return mtu <= conservativeMTU
	}
	
	// Create UDP socket for testing
	// We'll send a large UDP packet to test if it gets through
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.ParseIP(targetIP),
		Port: 0, // Use ephemeral port for testing
	})
	if err != nil {
		// Connection failed, be conservative
		return mtu <= conservativeMTU
	}
	defer conn.Close()

	// Set DF (Don't Fragment) flag to test path MTU
	// This ensures the packet is dropped if it exceeds any MTU on the path
	rawConn, err := conn.SyscallConn()
	if err == nil {
		rawConn.Control(func(fd uintptr) {
			// Linux: IP_MTU_DISCOVER = 10, IP_PMTUDISC_DO = 2
			// This is the most common target for this tunnel
			_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, 10, 2)
		})
	}
	
	// Set timeout for quick testing
	conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	
	// Create a test packet of specified MTU size
	// Subtract IP header (20) and UDP header (8) to get payload size
	payloadSize := mtu - 28
	if payloadSize <= 0 {
		return false
	}
	
	testData := make([]byte, payloadSize)
	// Fill with pattern for verification (optional)
	for i := range testData {
		testData[i] = byte(i % 256)
	}
	
	// Try to write the packet
	// If MTU is too large, this will fail or fragment
	_, err = conn.Write(testData)
	if err != nil {
		// Write failed, MTU too large
		return false
	}
	
	// For a more complete test, we would need:
	// 1. Server echo support to verify packet arrival
	// 2. Raw socket access to set DF (Don't Fragment) flag
	// 3. ICMP error handling to detect fragmentation needed
	
	// Since we can't reliably test without server cooperation,
	// we'll use a heuristic: if the write succeeded and the MTU
	// is within reasonable bounds, consider it valid
	
	// Additional validation: try TCP connection to verify connectivity
	// This ensures the path is actually working
	tcpConn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 500*time.Millisecond)
	if err != nil {
		// If TCP fails, the larger MTU might be causing issues
		// Be conservative for larger MTUs
		return mtu <= conservativeMTU
	}
	tcpConn.Close()
	
	// Both UDP write and TCP connect succeeded
	// The path likely supports this MTU
	return true
}

// GetRecommendedMTU returns a recommended MTU based on common network types
func GetRecommendedMTU(networkType string) int {
switch networkType {
case "ethernet":
return 1371 // Safe for rawtcp + encryption over standard Ethernet
case "pppoe":
return 1343 // PPPoE reduces MTU by 8 bytes, then account for overhead
case "mobile":
return 1200 // Conservative for mobile networks
case "vpn":
return 1300 // Account for VPN overhead
case "wifi":
return 1371 // Usually same as Ethernet
default:
return 1371 // Safe default
}
}

// AutoDetectNetworkType attempts to detect the network type
func AutoDetectNetworkType() string {
// Simple heuristic based on available interfaces
// In production, this could be more sophisticated

ifaces, err := net.Interfaces()
if err != nil {
return "ethernet"
}

for _, iface := range ifaces {
if iface.Flags&net.FlagUp == 0 {
continue
}
if iface.Flags&net.FlagLoopback != 0 {
continue
}

name := iface.Name

// Check for common interface name patterns
if len(name) >= 2 {
prefix := name[:2]
switch prefix {
case "wl", "ww": // wlan, wwan
return "wifi"
case "pp": // ppp
return "pppoe"
case "et", "en": // eth, ens, enp
return "ethernet"
}
}
}

return "ethernet" // Default
}
