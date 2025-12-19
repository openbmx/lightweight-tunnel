package tunnel

import (
	"net"
	"strings"
)

// parseRouteInfoPayload parses a route info payload in the format "TunnelIP|cidr1,cidr2"
// and returns the tunnel IP with the cleaned CIDR list.
// The sender uses comma-separated CIDRs without spaces; trimming here keeps the
// parser tolerant of accidental whitespace.
func parseRouteInfoPayload(payload []byte) (net.IP, []string) {
	parts := strings.SplitN(string(payload), "|", 2)
	if len(parts) != 2 {
		return nil, nil
	}

	ip := net.ParseIP(strings.TrimSpace(parts[0]))
	if ip == nil {
		return nil, nil
	}

	rawRoutes := strings.Split(parts[1], ",")
	clean := make([]string, 0, len(rawRoutes))
	for _, r := range rawRoutes {
		r = strings.TrimSpace(r)
		if r != "" {
			clean = append(clean, r)
		}
	}

	return ip, clean
}

// parseCIDRList validates and converts a list of CIDR strings to net.IPNet values.
// Invalid or non-IPv4 entries are filtered out and returned separately.
func parseCIDRList(routes []string) (valid []*net.IPNet, invalid []string) {
	for _, r := range routes {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(r)
		if err != nil || ipNet.IP.To4() == nil {
			invalid = append(invalid, r)
			continue
		}
		valid = append(valid, ipNet)
	}
	return valid, invalid
}

// chooseRouteClient selects the client IP string with the longest-prefix match
// for the given destination IP from the provided route map.
func chooseRouteClient(dst net.IP, routes map[string][]*net.IPNet) string {
	bestMask := -1
	bestClient := ""

	for clientIP, networks := range routes {
		for _, n := range networks {
			if n.Contains(dst) {
				ones, _ := n.Mask.Size()
				if ones > bestMask {
					bestMask = ones
					bestClient = clientIP
				}
			}
		}
	}

	return bestClient
}

// diffIPNets returns the routes that should be added and removed when moving
// from oldRoutes to newRoutes, using string representations for comparison.
func diffIPNets(oldRoutes, newRoutes []*net.IPNet) (toAdd, toDel []*net.IPNet) {
	oldMap := make(map[string]*net.IPNet, len(oldRoutes))
	newMap := make(map[string]*net.IPNet, len(newRoutes))

	for _, r := range oldRoutes {
		oldMap[r.String()] = r
	}
	for _, r := range newRoutes {
		newMap[r.String()] = r
	}

	for key, route := range newMap {
		if _, exists := oldMap[key]; !exists {
			toAdd = append(toAdd, route)
		}
	}
	for key, route := range oldMap {
		if _, exists := newMap[key]; !exists {
			toDel = append(toDel, route)
		}
	}
	return toAdd, toDel
}
