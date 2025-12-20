package tunnel

import (
	"bytes"
	"reflect"
	"testing"
	"unsafe"
)

func TestPrependPacketTypeInPlace(t *testing.T) {
	payload := []byte{0x1, 0x2, 0x3}
	buf := make([]byte, len(payload), len(payload)+1)
	copy(buf, payload)

	out, reused := prependPacketType(buf, 0xAA)
	if !reused {
		t.Fatalf("expected in-place reuse when capacity allows")
	}
	outHdr := (*reflect.SliceHeader)(unsafe.Pointer(&out))
	bufHdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
	if outHdr.Data != bufHdr.Data {
		t.Fatalf("expected slice to keep backing array after prepend")
	}
	if !bytes.Equal(out, []byte{0xAA, 0x1, 0x2, 0x3}) {
		t.Fatalf("unexpected data after prepend: %v", out)
	}
}

func TestPrependPacketTypeAllocatesWhenNoCapacity(t *testing.T) {
	payload := []byte{0x1, 0x2}

	out, reused := prependPacketType(payload, 0xBB)
	if reused {
		t.Fatalf("expected allocation when no spare capacity")
	}
	if &out[0] == &payload[0] {
		t.Fatalf("expected new backing array when allocating")
	}
	if !bytes.Equal(out, []byte{0xBB, 0x1, 0x2}) {
		t.Fatalf("unexpected data after prepend: %v", out)
	}
}
