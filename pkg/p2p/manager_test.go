package p2p

import (
	"net"
	"testing"
)

func TestFindPeerByAddrMatchesHostOnly(t *testing.T) {
	mgr := NewManager(0)
	peer := NewPeerInfo(net.ParseIP("10.0.0.2"))
	peer.PublicAddr = "8.8.8.8:1111"

	mgr.mu.Lock()
	mgr.peers[peer.TunnelIP.String()] = peer
	mgr.mu.Unlock()

	addr, _ := net.ResolveUDPAddr("udp4", "8.8.8.8:2222")
	if got := mgr.findPeerByAddr(addr); got == nil || !got.Equal(peer.TunnelIP) {
		t.Fatalf("expected peer IP %s, got %v", peer.TunnelIP, got)
	}
}
