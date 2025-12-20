package xdp

import (
	"encoding/binary"
	"sync"
)

// Accelerator provides a lightweight, user-space approximation of an
// eBPF/XDP classifier. It caches flow decisions to avoid repeatedly
// inspecting the same encrypted flows while keeping the code portable.
type Accelerator struct {
	enabled bool
	cache   sync.Map
}

// NewAccelerator creates a new accelerator. When disabled it simply
// delegates classification to the provided fallback.
func NewAccelerator(enabled bool) *Accelerator {
	return &Accelerator{enabled: enabled}
}

// Classify returns whether the packet should bypass outer encryption.
// The decision is cached per 5-tuple to mimic an XDP fast path.
func (a *Accelerator) Classify(ipPacket []byte, fallback func([]byte) bool) bool {
	if fallback == nil {
		return false
	}
	if !a.enabled {
		return fallback(ipPacket)
	}

	key, ok := flowKeyFromPacket(ipPacket)
	if !ok {
		return fallback(ipPacket)
	}

	if v, ok := a.cache.Load(key); ok {
		if cached, ok := v.(bool); ok {
			return cached
		}
	}

	result := fallback(ipPacket)
	a.cache.Store(key, result)
	return result
}

type flowKey struct {
	src     [4]byte
	dst     [4]byte
	srcPort uint16
	dstPort uint16
	proto   uint8
}

func flowKeyFromPacket(ipPacket []byte) (flowKey, bool) {
	if len(ipPacket) < 20 {
		return flowKey{}, false
	}
	if ipPacket[0]>>4 != 4 {
		return flowKey{}, false
	}

	ihl := int(ipPacket[0]&0x0F) * 4
	if len(ipPacket) < ihl {
		return flowKey{}, false
	}

	var key flowKey
	copy(key.src[:], ipPacket[12:16])
	copy(key.dst[:], ipPacket[16:20])
	key.proto = ipPacket[9]

	switch key.proto {
	case 6, 17: // TCP or UDP
		if len(ipPacket) < ihl+4 {
			return flowKey{}, false
		}
		payload := ipPacket[ihl:]
		key.srcPort = binary.BigEndian.Uint16(payload[0:2])
		key.dstPort = binary.BigEndian.Uint16(payload[2:4])
	default:
		// Non-TCP/UDP protocols use zero ports to keep cache key stable
	}

	return key, true
}

// Flush clears cached flow decisions.
func (a *Accelerator) Flush() {
	a.cache = sync.Map{}
}
