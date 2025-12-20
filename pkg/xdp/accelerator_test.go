package xdp

import (
	"encoding/binary"
	"testing"
)

func makeTestIPv4Packet(proto byte, srcPort, dstPort uint16) []byte {
	// Minimal IPv4 header (20 bytes) + 4 bytes for src/dst ports.
	packet := make([]byte, 24)
	packet[0] = (ipv4Version << 4) | 5
	packet[9] = proto
	copy(packet[12:16], []byte{1, 2, 3, 4})
	copy(packet[16:20], []byte{5, 6, 7, 8})

	payload := packet[20:]
	binary.BigEndian.PutUint16(payload[0:2], srcPort)
	binary.BigEndian.PutUint16(payload[2:4], dstPort)
	return packet
}

func TestAcceleratorCachesFlowDecision(t *testing.T) {
	accel := NewAccelerator(true)
	packet := makeTestIPv4Packet(ipProtoTCP, 12345, 443)

	callCount := 0
	fallback := func([]byte) bool {
		callCount++
		return true
	}

	if !accel.Classify(packet, fallback) {
		t.Fatalf("expected classifier to return true")
	}
	if !accel.Classify(packet, fallback) {
		t.Fatalf("expected cached classifier result to be true")
	}
	if callCount != 1 {
		t.Fatalf("expected fallback to run once, got %d", callCount)
	}
}

func TestAcceleratorFlushResetsCache(t *testing.T) {
	accel := NewAccelerator(true)
	packet := makeTestIPv4Packet(ipProtoUDP, 10000, 2053)

	callCount := 0
	fallback := func([]byte) bool {
		callCount++
		return callCount%2 == 1
	}

	if !accel.Classify(packet, fallback) {
		t.Fatalf("expected first classification to return true")
	}
	accel.Flush()
	if accel.Classify(packet, fallback) {
		t.Fatalf("expected fallback result after flush to be false")
	}
	if callCount != 2 {
		t.Fatalf("expected fallback to run twice after flush, got %d", callCount)
	}
}

func TestAcceleratorDisabledFallsBack(t *testing.T) {
	accel := NewAccelerator(false)
	packet := makeTestIPv4Packet(ipProtoTCP, 80, 8080)

	callCount := 0
	fallback := func([]byte) bool {
		callCount++
		return false
	}

	_ = accel.Classify(packet, fallback)
	_ = accel.Classify(packet, fallback)

	if callCount != 2 {
		t.Fatalf("expected fallback to run for each call when disabled, got %d", callCount)
	}
}
