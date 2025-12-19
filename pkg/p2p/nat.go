package p2p

import (
	"net"
)

// NATType represents a simplified NAT classification.
// The values are ordered from least to most restrictive for prioritization.
type NATType string

const (
	NATUnknown            NATType = "unknown"
	NATOpenOrFullCone     NATType = "full_cone"
	NATRestrictedCone     NATType = "restricted_cone"
	NATPortRestrictedCone NATType = "port_restricted_cone"
	NATSymmetric          NATType = "symmetric"
)

// priority returns a lower score for less restrictive NAT types.
func (n NATType) priority() int {
	switch n {
	case NATOpenOrFullCone:
		return 1
	case NATRestrictedCone:
		return 2
	case NATPortRestrictedCone:
		return 3
	case NATSymmetric:
		return 4
	default:
		return 5
	}
}

// ParseNATType converts a string into a NATType, defaulting to NATUnknown.
func ParseNATType(raw string) NATType {
	switch NATType(raw) {
	case NATOpenOrFullCone, NATRestrictedCone, NATPortRestrictedCone, NATSymmetric:
		return NATType(raw)
	default:
		return NATUnknown
	}
}

// DetectNATType performs a lightweight NAT type guess by comparing the local
// socket address with the public address observed by the server.
// This is heuristic and intended to guide connection priority:
//   - Matching host and port: likely no NAT/full cone
//   - Different host but same port: port is preserved (restricted/port-restricted)
//   - Different host and port: likely symmetric NAT
func DetectNATType(localAddr, publicAddr string) NATType {
	localHost, localPort, errLocal := net.SplitHostPort(localAddr)
	publicHost, publicPort, errPublic := net.SplitHostPort(publicAddr)
	if errLocal != nil || errPublic != nil {
		return NATUnknown
	}

	switch {
	case publicHost == localHost && publicPort == localPort:
		return NATOpenOrFullCone
	case publicPort == localPort:
		return NATPortRestrictedCone
	default:
		return NATSymmetric
	}
}
