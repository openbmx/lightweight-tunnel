package nat

import (
	"fmt"
	"testing"
)

func TestNATTypeString(t *testing.T) {
	tests := []struct {
		natType  NATType
		expected string
	}{
		{NATNone, "None (Public IP)"},
		{NATFullCone, "Full Cone"},
		{NATRestrictedCone, "Restricted Cone"},
		{NATPortRestrictedCone, "Port-Restricted Cone"},
		{NATSymmetric, "Symmetric"},
		{NATUnknown, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.natType.String()
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestNATTypeGetLevel(t *testing.T) {
	tests := []struct {
		natType  NATType
		expected int
	}{
		{NATNone, 0},
		{NATFullCone, 1},
		{NATRestrictedCone, 2},
		{NATPortRestrictedCone, 3},
		{NATSymmetric, 4},
		{NATUnknown, 5},
	}

	for _, tt := range tests {
		t.Run(tt.natType.String(), func(t *testing.T) {
			result := tt.natType.GetLevel()
			if result != tt.expected {
				t.Errorf("Expected level %d for %s, got %d", tt.expected, tt.natType, result)
			}
		})
	}
}

func TestNATTypeCanTraverseWith(t *testing.T) {
	tests := []struct {
		nat1     NATType
		nat2     NATType
		expected bool
		name     string
	}{
		{NATNone, NATSymmetric, true, "None with Symmetric should work"},
		{NATFullCone, NATSymmetric, true, "FullCone with Symmetric should work"},
		{NATSymmetric, NATSymmetric, false, "Symmetric with Symmetric should fail"},
		{NATRestrictedCone, NATPortRestrictedCone, true, "Cone NATs should work together"},
		{NATPortRestrictedCone, NATPortRestrictedCone, true, "Same type should work"},
		{NATSymmetric, NATRestrictedCone, true, "Symmetric with Cone should attempt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.nat1.CanTraverseWith(tt.nat2)
			if result != tt.expected {
				t.Errorf("Expected %v for %s with %s, got %v",
					tt.expected, tt.nat1, tt.nat2, result)
			}
		})
	}
}

func TestNATTypeShouldInitiateConnection(t *testing.T) {
	tests := []struct {
		nat1     NATType
		nat2     NATType
		expected bool
		name     string
	}{
		{NATNone, NATSymmetric, true, "Better NAT should initiate (None to Symmetric)"},
		{NATFullCone, NATSymmetric, true, "Better NAT should initiate (FullCone to Symmetric)"},
		{NATSymmetric, NATFullCone, false, "Worse NAT should not initiate (Symmetric to FullCone)"},
		{NATRestrictedCone, NATPortRestrictedCone, true, "Better NAT should initiate"},
		{NATPortRestrictedCone, NATRestrictedCone, false, "Worse NAT should not initiate"},
		{NATFullCone, NATFullCone, false, "Same level should not initiate"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.nat1.ShouldInitiateConnection(tt.nat2)
			if result != tt.expected {
				t.Errorf("Expected %v for %s initiating to %s, got %v",
					tt.expected, tt.nat1, tt.nat2, result)
			}
		})
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"127.0.0.1", true}, // Loopback
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := parseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tt.ip)
			}
			result := isPrivateIP(ip)
			if result != tt.expected {
				t.Errorf("Expected %v for %s, got %v", tt.expected, tt.ip, result)
			}
		})
	}
}

// Helper function for testing
func parseIP(s string) []byte {
	ip := make([]byte, 4)
	var a, b, c, d int
	if n, _ := fmt.Sscanf(s, "%d.%d.%d.%d", &a, &b, &c, &d); n == 4 {
		ip[0], ip[1], ip[2], ip[3] = byte(a), byte(b), byte(c), byte(d)
		return ip
	}
	return nil
}
