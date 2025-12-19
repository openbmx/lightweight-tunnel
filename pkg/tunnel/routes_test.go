package tunnel

import (
	"net"
	"testing"
)

func TestParseRouteInfoPayload(t *testing.T) {
	ip, routes := parseRouteInfoPayload([]byte("10.0.0.2|192.168.1.0/24, 10.1.0.0/16"))
	if ip == nil || !ip.Equal(net.ParseIP("10.0.0.2")) {
		t.Fatalf("expected tunnel IP 10.0.0.2, got %v", ip)
	}
	if len(routes) != 2 || routes[0] != "192.168.1.0/24" || routes[1] != "10.1.0.0/16" {
		t.Fatalf("unexpected routes: %v", routes)
	}

	// Invalid payload should return nil
	ip, routes = parseRouteInfoPayload([]byte("invalid"))
	if ip != nil || routes != nil {
		t.Fatalf("expected nil result for invalid payload, got %v %v", ip, routes)
	}
}

func TestParseCIDRList(t *testing.T) {
	valid, invalid := parseCIDRList([]string{"192.168.1.0/24", "bad", "2001:db8::/32"})
	if len(valid) != 1 || valid[0].String() != "192.168.1.0/24" {
		t.Fatalf("expected one valid IPv4 network, got %v", valid)
	}
	if len(invalid) != 2 {
		t.Fatalf("expected two invalid entries, got %d", len(invalid))
	}
}

func TestChooseRouteClient(t *testing.T) {
	routes := map[string][]*net.IPNet{}

	_, netA, _ := net.ParseCIDR("192.168.0.0/16")
	_, netB, _ := net.ParseCIDR("192.168.1.0/24")
	_, netC, _ := net.ParseCIDR("10.0.0.0/8")

	routes["10.0.0.2"] = []*net.IPNet{netA}
	routes["10.0.0.3"] = []*net.IPNet{netB, netC}

	dst := net.ParseIP("192.168.1.42")
	client := chooseRouteClient(dst, routes)
	if client != "10.0.0.3" {
		t.Fatalf("expected longest prefix client 10.0.0.3, got %s", client)
	}

	// No match
	dst = net.ParseIP("172.16.0.1")
	client = chooseRouteClient(dst, routes)
	if client != "" {
		t.Fatalf("expected no match, got %s", client)
	}
}

func TestDiffIPNets(t *testing.T) {
	_, a, _ := net.ParseCIDR("10.0.0.0/24")
	_, b, _ := net.ParseCIDR("10.0.1.0/24")
	_, c, _ := net.ParseCIDR("10.0.2.0/24")

	toAdd, toDel := diffIPNets([]*net.IPNet{a, b}, []*net.IPNet{b, c})
	if len(toAdd) != 1 || toAdd[0].String() != "10.0.2.0/24" {
		t.Fatalf("unexpected toAdd: %v", toAdd)
	}
	if len(toDel) != 1 || toDel[0].String() != "10.0.0.0/24" {
		t.Fatalf("unexpected toDel: %v", toDel)
	}
}
