package nat

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

// STUN protocol constants (RFC 5389)
const (
	// STUN message types
	stunBindingRequest         = 0x0001
	stunBindingResponse        = 0x0101
	stunBindingErrorResponse   = 0x0111

	// STUN magic cookie (RFC 5389)
	stunMagicCookie = 0x2112A442

	// STUN attribute types
	stunAttrMappedAddress     = 0x0001
	stunAttrChangeRequest     = 0x0003
	stunAttrSourceAddress     = 0x0004
	stunAttrChangedAddress    = 0x0005
	stunAttrXorMappedAddress  = 0x0020
	stunAttrResponseOrigin    = 0x802b
	stunAttrOtherAddress      = 0x802c

	// STUN header size
	stunHeaderSize = 20

	// Default STUN server port
	stunDefaultPort = 3478

	// STUN timeout
	stunTimeout = 3 * time.Second
)

var (
	// ErrSTUNTimeout indicates STUN request timed out
	ErrSTUNTimeout = errors.New("STUN request timeout")
	// ErrSTUNInvalidResponse indicates invalid STUN response
	ErrSTUNInvalidResponse = errors.New("invalid STUN response")
	// ErrSTUNNoMappedAddress indicates no mapped address in response
	ErrSTUNNoMappedAddress = errors.New("no mapped address in STUN response")
)

// STUNClient handles STUN protocol communication
type STUNClient struct {
	serverAddr string
	timeout    time.Duration
}

// NewSTUNClient creates a new STUN client
func NewSTUNClient(serverAddr string, timeout time.Duration) *STUNClient {
	if timeout == 0 {
		timeout = stunTimeout
	}
	return &STUNClient{
		serverAddr: serverAddr,
		timeout:    timeout,
	}
}

// STUNResult contains the result of a STUN query
type STUNResult struct {
	MappedAddr    *net.UDPAddr
	SourceAddr    *net.UDPAddr
	ChangedAddr   *net.UDPAddr
	OtherAddr     *net.UDPAddr
}

// Query performs a STUN binding request
func (c *STUNClient) Query(localAddr *net.UDPAddr, changeIP, changePort bool) (*STUNResult, error) {
	// Resolve server address first
	serverUDPAddr, err := net.ResolveUDPAddr("udp4", c.serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve STUN server: %v", err)
	}

	// Use ListenUDP for consistent connection handling
	// This allows us to optionally bind to a specific local address
	conn, err := net.ListenUDP("udp4", localAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP connection: %v", err)
	}
	defer conn.Close()

	// Generate transaction ID
	transactionID := make([]byte, 12)
	if _, err := rand.Read(transactionID); err != nil {
		return nil, fmt.Errorf("failed to generate transaction ID: %v", err)
	}

	// Build STUN binding request
	request := c.buildBindingRequest(transactionID, changeIP, changePort)

	// Set deadline
	conn.SetDeadline(time.Now().Add(c.timeout))

	// Send request to server
	_, err = conn.WriteToUDP(request, serverUDPAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to send STUN request: %v", err)
	}

	// Receive response
	buffer := make([]byte, 1500)
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, ErrSTUNTimeout
		}
		return nil, fmt.Errorf("failed to receive STUN response: %v", err)
	}

	// Parse response
	result, err := c.parseBindingResponse(buffer[:n], transactionID)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// buildBindingRequest creates a STUN binding request message
func (c *STUNClient) buildBindingRequest(transactionID []byte, changeIP, changePort bool) []byte {
	message := make([]byte, stunHeaderSize)

	// Message type (Binding Request = 0x0001)
	binary.BigEndian.PutUint16(message[0:2], stunBindingRequest)

	// Message length (will update after adding attributes)
	messageLength := 0

	// Magic cookie
	binary.BigEndian.PutUint32(message[4:8], stunMagicCookie)

	// Transaction ID (12 bytes)
	copy(message[8:20], transactionID)

	// Add CHANGE-REQUEST attribute if needed
	if changeIP || changePort {
		attr := make([]byte, 8)
		binary.BigEndian.PutUint16(attr[0:2], stunAttrChangeRequest)
		binary.BigEndian.PutUint16(attr[2:4], 4) // Length
		
		flags := uint32(0)
		if changeIP {
			flags |= 0x04
		}
		if changePort {
			flags |= 0x02
		}
		binary.BigEndian.PutUint32(attr[4:8], flags)
		
		message = append(message, attr...)
		messageLength += 8
	}

	// Update message length
	binary.BigEndian.PutUint16(message[2:4], uint16(messageLength))

	return message
}

// parseBindingResponse parses a STUN binding response
func (c *STUNClient) parseBindingResponse(data []byte, expectedTransactionID []byte) (*STUNResult, error) {
	if len(data) < stunHeaderSize {
		return nil, ErrSTUNInvalidResponse
	}

	// Check message type
	messageType := binary.BigEndian.Uint16(data[0:2])
	if messageType != stunBindingResponse {
		return nil, fmt.Errorf("unexpected message type: 0x%04x", messageType)
	}

	// Verify magic cookie
	magicCookie := binary.BigEndian.Uint32(data[4:8])
	if magicCookie != stunMagicCookie {
		return nil, ErrSTUNInvalidResponse
	}

	// Verify transaction ID
	transactionID := data[8:20]
	for i := 0; i < 12; i++ {
		if transactionID[i] != expectedTransactionID[i] {
			return nil, ErrSTUNInvalidResponse
		}
	}

	// Parse attributes
	messageLength := binary.BigEndian.Uint16(data[2:4])
	result := &STUNResult{}
	
	offset := stunHeaderSize
	for offset < stunHeaderSize+int(messageLength) {
		if offset+4 > len(data) {
			break
		}

		attrType := binary.BigEndian.Uint16(data[offset : offset+2])
		attrLength := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4

		if offset+int(attrLength) > len(data) {
			break
		}

		attrValue := data[offset : offset+int(attrLength)]

		switch attrType {
		case stunAttrMappedAddress:
			result.MappedAddr = c.parseAddress(attrValue)
		case stunAttrXorMappedAddress:
			result.MappedAddr = c.parseXorAddress(attrValue, transactionID)
		case stunAttrSourceAddress:
			result.SourceAddr = c.parseAddress(attrValue)
		case stunAttrChangedAddress:
			result.ChangedAddr = c.parseAddress(attrValue)
		case stunAttrOtherAddress:
			result.OtherAddr = c.parseAddress(attrValue)
		}

		// Move to next attribute (with padding)
		offset += int(attrLength)
		// Attributes are padded to 4-byte boundary
		if attrLength%4 != 0 {
			offset += 4 - int(attrLength)%4
		}
	}

	if result.MappedAddr == nil {
		return nil, ErrSTUNNoMappedAddress
	}

	return result, nil
}

// parseAddress parses a STUN address attribute
func (c *STUNClient) parseAddress(data []byte) *net.UDPAddr {
	if len(data) < 8 {
		return nil
	}

	family := data[1]
	if family != 0x01 { // IPv4
		return nil
	}

	port := binary.BigEndian.Uint16(data[2:4])
	ip := net.IPv4(data[4], data[5], data[6], data[7])

	return &net.UDPAddr{IP: ip, Port: int(port)}
}

// parseXorAddress parses a XOR-MAPPED-ADDRESS attribute
func (c *STUNClient) parseXorAddress(data []byte, transactionID []byte) *net.UDPAddr {
	if len(data) < 8 {
		return nil
	}

	family := data[1]
	if family != 0x01 { // IPv4
		return nil
	}

	// XOR port with most significant 16 bits of magic cookie
	xorPort := binary.BigEndian.Uint16(data[2:4])
	port := xorPort ^ uint16(stunMagicCookie>>16)

	// XOR IP with magic cookie
	xorIP := binary.BigEndian.Uint32(data[4:8])
	ipAddr := xorIP ^ stunMagicCookie

	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipAddr)

	return &net.UDPAddr{IP: ip, Port: int(port)}
}

// DetectNATTypeWithSTUN performs NAT type detection using STUN
// Based on RFC 3489 NAT behavior discovery algorithm
// localAddr specifies the local address to bind to (must match the P2P port for accurate detection)
func (c *STUNClient) DetectNATTypeWithSTUN(localAddr *net.UDPAddr) (NATType, error) {
	// Test 1: Basic connectivity and check if we have a public IP
	result1, err := c.Query(localAddr, false, false)
	if err != nil {
		return NATUnknown, fmt.Errorf("test 1 failed: %v", err)
	}

	// Check if mapped address equals local address (no NAT)
	localAddrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range localAddrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.Equal(result1.MappedAddr.IP) {
					return NATNone, nil
				}
			}
		}
	}

	// We're behind NAT, continue testing
	// Test 2: Request response from different IP and port
	result2, err := c.Query(localAddr, true, true)
	if err == nil && result2 != nil {
		// If we receive a response, it's a Full Cone NAT
		return NATFullCone, nil
	}

	// Test 3: Request response from same IP but different port
	result3, err := c.Query(localAddr, false, true)
	if err == nil && result3 != nil {
		// Received response from different port = Restricted Cone NAT
		return NATRestrictedCone, nil
	}

	// Test 4: Check if port mapping is consistent (symmetric test)
	// Use different destination to see if we get different mapped port
	alternateServer := result1.ChangedAddr
	if alternateServer == nil {
		alternateServer = result1.OtherAddr
	}
	
	if alternateServer != nil {
		// Query alternate server using same local port
		alternateClient := NewSTUNClient(alternateServer.String(), c.timeout)
		result4, err := alternateClient.Query(localAddr, false, false)
		if err == nil && result4 != nil {
			// Compare ports
			if result1.MappedAddr.Port != result4.MappedAddr.Port {
				// Different port for different destination = Symmetric NAT
				return NATSymmetric, nil
			}
		}
	}

	// Default to Port-Restricted Cone NAT
	// This is the most common type and safest assumption
	return NATPortRestrictedCone, nil
}

// GetPublicAddress returns the public IP and port as seen by the STUN server
func (c *STUNClient) GetPublicAddress(localAddr *net.UDPAddr) (*net.UDPAddr, error) {
	result, err := c.Query(localAddr, false, false)
	if err != nil {
		return nil, err
	}
	return result.MappedAddr, nil
}
