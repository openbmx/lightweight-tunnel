package tunnel

import (
	"encoding/binary"
)

var encryptedServicePorts = map[uint16]struct{}{
	443:   {},
	8443:  {},
	853:   {},
	2053:  {},
	3389:  {},
	8388:  {},
	8389:  {},
	10086: {},
	10443: {},
}

func portLikelyEncrypted(port uint16) bool {
	_, ok := encryptedServicePorts[port]
	return ok
}

// isLikelyEncryptedTraffic inspects the inner IP packet to detect TLS- or AEAD-
// protected traffic (e.g., Shadowsocks/vmess/vless). When detected, we can skip
// outer AES to avoid double encryption.
func isLikelyEncryptedTraffic(ipPacket []byte) bool {
	if len(ipPacket) < IPv4MinHeaderLen || ipPacket[0]>>4 != IPv4Version {
		return false
	}

	ihl := int(ipPacket[0]&0x0F) * 4
	if len(ipPacket) < ihl+4 {
		return false
	}

	proto := ipPacket[9]
	payload := ipPacket[ihl:]

	switch proto {
	case 6: // TCP
		if len(payload) < 20 {
			return false
		}
		srcPort := binary.BigEndian.Uint16(payload[0:2])
		dstPort := binary.BigEndian.Uint16(payload[2:4])
		dataOffset := int(payload[12]>>4) * 4
		if dataOffset > len(payload) {
			return false
		}
		appPayload := payload[dataOffset:]
		return portLikelyEncrypted(srcPort) || portLikelyEncrypted(dstPort) ||
			looksLikeTLS(appPayload) || looksLikeAEADProxy(appPayload)
	case 17: // UDP (QUIC or Shadowsocks)
		if len(payload) < 8 {
			return false
		}
		srcPort := binary.BigEndian.Uint16(payload[0:2])
		dstPort := binary.BigEndian.Uint16(payload[2:4])
		appPayload := payload[8:]
		return portLikelyEncrypted(srcPort) || portLikelyEncrypted(dstPort) ||
			looksLikeQUIC(appPayload) || looksLikeAEADProxy(appPayload)
	default:
		return false
	}
}

func looksLikeTLS(payload []byte) bool {
	if len(payload) < 5 {
		return false
	}
	recordType := payload[0]
	versionMajor := payload[1]
	versionMinor := payload[2]
	if versionMajor != 0x03 {
		return false
	}
	if recordType == 0x16 || recordType == 0x14 || recordType == 0x17 || recordType == 0x15 {
		// Accept TLS 1.0 - 1.3
		return versionMinor <= 0x04
	}
	return false
}

func looksLikeQUIC(payload []byte) bool {
	if len(payload) < 5 {
		return false
	}
	first := payload[0]
	// QUIC long header: 0b1xxxxxxx, short header: 0b0xxxxxxx with spin bit.
	if first&0x80 == 0x80 {
		return true
	}
	// Short header still likely encrypted; treat as encrypted when payload is non-empty.
	return len(payload) > 16
}

func looksLikeAEADProxy(payload []byte) bool {
	if len(payload) < 3 {
		return false
	}
	// Shadowsocks/VMess/VLESS commonly start with address type (1/3/4) or random nonce bytes.
	atyp := payload[0]
	switch atyp {
	case 0x01:
		return len(payload) >= 1+4+2 // IPv4 addr + port
	case 0x04:
		return len(payload) >= 1+16+2 // IPv6 addr + port
	case 0x03:
		domainLen := int(payload[1])
		return len(payload) >= 2+domainLen+2
	default:
		// If it looks like high-entropy nonce (non-printable and non-ASCII), treat as encrypted.
		nonPrintable := 0
		checkLen := len(payload)
		if checkLen > 8 {
			checkLen = 8
		}
		for i := 0; i < checkLen; i++ {
			if payload[i] < 0x20 || payload[i] > 0x7E {
				nonPrintable++
			}
		}
		return nonPrintable >= checkLen-1
	}
}

func isPlainPassThroughPacket(packet []byte) bool {
	if len(packet) < 1 || packet[0] != PacketTypeData {
		return false
	}
	return isLikelyEncryptedTraffic(packet[1:])
}
