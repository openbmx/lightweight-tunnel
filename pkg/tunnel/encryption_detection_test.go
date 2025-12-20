package tunnel

import (
	"encoding/binary"
	"reflect"
	"testing"

	"github.com/openbmx/lightweight-tunnel/pkg/crypto"
)

func buildTLSPacket(dstPort uint16) []byte {
	ip := make([]byte, 20+20+5)
	ip[0] = 0x45                       // IPv4, IHL=5
	ip[9] = 6                          // TCP
	copy(ip[12:], []byte{10, 0, 0, 1}) // src
	copy(ip[16:], []byte{10, 0, 0, 2}) // dst

	tcp := ip[20:]
	binary.BigEndian.PutUint16(tcp[0:], 12345)
	binary.BigEndian.PutUint16(tcp[2:], dstPort)
	tcp[12] = 0x50 // data offset=5, flags empty
	copy(tcp[20:], []byte{0x16, 0x03, 0x03, 0x00, 0x10})
	return ip
}

func buildHTTPPacket() []byte {
	ip := buildTLSPacket(80)
	tcp := ip[20:]
	copy(tcp[20:], []byte("GET / HTTP/1.1"))
	return ip
}

func TestIsLikelyEncryptedTraffic_TLS(t *testing.T) {
	ip := buildTLSPacket(443)
	if !isLikelyEncryptedTraffic(ip) {
		t.Fatalf("expected TLS-like packet to be treated as encrypted")
	}
}

func TestIsLikelyEncryptedTraffic_HTTP(t *testing.T) {
	ip := buildHTTPPacket()
	if isLikelyEncryptedTraffic(ip) {
		t.Fatalf("expected plain HTTP-like packet to not be treated as encrypted")
	}
}

func TestEncryptDecryptSkipDoubleEncryption(t *testing.T) {
	ip := buildTLSPacket(443)
	packet := append([]byte{PacketTypeData}, ip...)

	c, err := crypto.NewCipher("skip-double-encryption")
	if err != nil {
		t.Fatalf("cipher init failed: %v", err)
	}

	tun := &Tunnel{cipher: c}

	encrypted, err := tun.encryptPacket(packet)
	if err != nil {
		t.Fatalf("encryptPacket returned error: %v", err)
	}
	if !reflect.DeepEqual(encrypted, packet) {
		t.Fatalf("encrypted packet should be unchanged for already encrypted inner traffic")
	}

	plain, usedCipher, gen, err := tun.decryptWithFallback(packet)
	if err != nil {
		t.Fatalf("decryptWithFallback returned error: %v", err)
	}
	if usedCipher != nil || gen != 0 {
		t.Fatalf("expected decryptWithFallback to bypass cipher for plain packet")
	}
	if !reflect.DeepEqual(plain, packet) {
		t.Fatalf("expected decrypted packet to match original")
	}
}
