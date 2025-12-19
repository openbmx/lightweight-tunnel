package tunnel

import (
	"bytes"
	"testing"
)

func TestTLSLikeFrameRoundTrip(t *testing.T) {
	payload := []byte("hello-dpi-evasion")
	frame, err := buildTLSLikeFrame(payload, 16)
	if err != nil {
		t.Fatalf("buildTLSLikeFrame returned error: %v", err)
	}

	if len(frame) < tlsRecordHeaderLen+tlsObfsLengthField+len(payload) {
		t.Fatalf("unexpected frame length: %d", len(frame))
	}
	if len(frame) > tlsRecordHeaderLen+tlsObfsLengthField+len(payload)+16 {
		t.Fatalf("frame length exceeded padding limit: %d", len(frame))
	}

	decoded, err := parseTLSLikeFrame(frame)
	if err != nil {
		t.Fatalf("parseTLSLikeFrame returned error: %v", err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("decoded payload mismatch, got %q want %q", decoded, payload)
	}
}

func TestTLSLikeFrameInvalidInput(t *testing.T) {
	if _, err := parseTLSLikeFrame([]byte{0x17, 0x03, 0x03}); err == nil {
		t.Fatalf("expected error for short frame")
	}
}
