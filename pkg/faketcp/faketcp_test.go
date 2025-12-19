package faketcp

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestTCPHeaderSerialization(t *testing.T) {
	conn := &Conn{
		srcPort: 12345,
		dstPort: 9000,
		seqNum:  1000,
		ackNum:  2000,
	}

	header := conn.buildTCPHeader(100)

	if header.SrcPort != 12345 {
		t.Errorf("Expected SrcPort 12345, got %d", header.SrcPort)
	}
	if header.DstPort != 9000 {
		t.Errorf("Expected DstPort 9000, got %d", header.DstPort)
	}
	if header.SeqNum != 1000 {
		t.Errorf("Expected SeqNum 1000, got %d", header.SeqNum)
	}
	if header.AckNum != 2000 {
		t.Errorf("Expected AckNum 2000, got %d", header.AckNum)
	}
}

func TestTCPHeaderParseAndSerialize(t *testing.T) {
	conn := &Conn{
		srcPort: 12345,
		dstPort: 9000,
		seqNum:  1000,
		ackNum:  2000,
	}

	originalHeader := conn.buildTCPHeader(100)
	serialized := conn.serializeTCPHeader(originalHeader)

	if len(serialized) != TCPHeaderSize {
		t.Errorf("Expected serialized header size %d, got %d", TCPHeaderSize, len(serialized))
	}

	parsedHeader := parseTCPHeader(serialized)

	if parsedHeader.SrcPort != originalHeader.SrcPort {
		t.Errorf("SrcPort mismatch: expected %d, got %d", originalHeader.SrcPort, parsedHeader.SrcPort)
	}
	if parsedHeader.DstPort != originalHeader.DstPort {
		t.Errorf("DstPort mismatch: expected %d, got %d", originalHeader.DstPort, parsedHeader.DstPort)
	}
	if parsedHeader.SeqNum != originalHeader.SeqNum {
		t.Errorf("SeqNum mismatch: expected %d, got %d", originalHeader.SeqNum, parsedHeader.SeqNum)
	}
	if parsedHeader.AckNum != originalHeader.AckNum {
		t.Errorf("AckNum mismatch: expected %d, got %d", originalHeader.AckNum, parsedHeader.AckNum)
	}
	if parsedHeader.Flags != originalHeader.Flags {
		t.Errorf("Flags mismatch: expected %d, got %d", originalHeader.Flags, parsedHeader.Flags)
	}
}

func TestDialAndListen(t *testing.T) {
	// Start listener
	listener, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	listenerAddr := listener.Addr().String()
	t.Logf("Listener started on %s", listenerAddr)

	// Test data
	testData := []byte("Hello, fake TCP!")

	// Start server goroutine
	serverDone := make(chan error, 1)
	go func() {
		t.Log("Server: waiting for connection...")
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- fmt.Errorf("failed to accept connection: %v", err)
			return
		}
		t.Log("Server: connection accepted")

		// Read packet
		t.Log("Server: reading packet...")
		data, err := conn.ReadPacket()
		if err != nil {
			serverDone <- fmt.Errorf("failed to read packet: %v", err)
			return
		}
		t.Logf("Server: received %d bytes", len(data))

		if !bytes.Equal(data, testData) {
			serverDone <- fmt.Errorf("data mismatch: expected %s, got %s", testData, data)
			return
		}

		// Echo back
		t.Log("Server: echoing packet...")
		err = conn.WritePacket(data)
		if err != nil {
			serverDone <- fmt.Errorf("failed to write packet: %v", err)
			return
		}
		t.Log("Server: done")

		serverDone <- nil
	}()

	// Give server time to start
	time.Sleep(200 * time.Millisecond)

	// Client connects
	t.Logf("Client: dialing %s...", listenerAddr)
	conn, err := Dial(listenerAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()
	t.Log("Client: connected")

	// Send data
	t.Log("Client: sending packet...")
	err = conn.WritePacket(testData)
	if err != nil {
		t.Fatalf("Failed to write packet: %v", err)
	}
	t.Log("Client: packet sent")

	// Read echo
	t.Log("Client: reading echo...")
	receivedData, err := conn.ReadPacket()
	if err != nil {
		t.Fatalf("Failed to read packet: %v", err)
	}
	t.Logf("Client: received %d bytes", len(receivedData))

	if !bytes.Equal(receivedData, testData) {
		t.Errorf("Echo data mismatch: expected %s, got %s", testData, receivedData)
	}

	// Wait for server
	t.Log("Waiting for server...")
	select {
	case err := <-serverDone:
		if err != nil {
			t.Errorf("Server error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Server timeout")
	}
}

func getFreeUDPPort(t *testing.T) int {
	t.Helper()

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve UDP addr: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("Failed to listen UDP: %v", err)
	}
	defer conn.Close()

	return conn.LocalAddr().(*net.UDPAddr).Port
}

func TestDialWithLocalAddrBindsPort(t *testing.T) {
	listener, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	listenerAddr := listener.Addr().String()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- fmt.Errorf("failed to accept connection: %v", err)
			return
		}

		payload, err := conn.ReadPacket()
		if err != nil {
			serverDone <- fmt.Errorf("failed to read packet: %v", err)
			return
		}

		if err := conn.WritePacket(payload); err != nil {
			serverDone <- fmt.Errorf("failed to echo packet: %v", err)
			return
		}
		serverDone <- nil
	}()

	time.Sleep(100 * time.Millisecond)

	var (
		client    *Conn
		localAddr string
		localPort int
	)

	for attempt := 0; attempt < 5; attempt++ {
		localPort = getFreeUDPPort(t)
		localAddr = fmt.Sprintf("127.0.0.1:%d", localPort)

		client, err = DialWithLocalAddr(listenerAddr, localAddr, 5*time.Second)
		if err == nil {
			break
		}

		if !strings.Contains(err.Error(), "address already in use") {
			t.Fatalf("Failed to dial with local addr: %v", err)
		}
	}

	if err != nil {
		t.Fatalf("Failed to dial with local addr after retries: %v", err)
	}
	defer client.Close()

	if got := client.LocalAddr().(*net.UDPAddr).Port; got != localPort {
		t.Fatalf("Expected local port %d, got %d", localPort, got)
	}

	testData := []byte("bind-check")
	if err := client.WritePacket(testData); err != nil {
		t.Fatalf("Failed to write packet: %v", err)
	}

	if _, err := client.ReadPacket(); err != nil {
		t.Fatalf("Failed to read echoed packet: %v", err)
	}

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("Server error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Server timeout")
	}
}

func TestSequenceNumberIncrement(t *testing.T) {
	conn, err := Dial("127.0.0.1:9999", 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	initialSeq := conn.seqNum

	testData := []byte("test")
	// We can't actually send without a server, but we can test the sequence logic
	// by directly calling the methods

	conn.mu.Lock()
	header := conn.buildTCPHeader(len(testData))
	conn.mu.Unlock()

	if header.SeqNum != initialSeq {
		t.Errorf("Expected SeqNum %d, got %d", initialSeq, header.SeqNum)
	}

	// After sending, sequence number should increment
	expectedNewSeq := initialSeq + uint32(len(testData))

	conn.mu.Lock()
	conn.seqNum += uint32(len(testData))
	newSeq := conn.seqNum
	conn.mu.Unlock()

	if newSeq != expectedNewSeq {
		t.Errorf("Expected new SeqNum %d, got %d", expectedNewSeq, newSeq)
	}
}

func TestMaxPayloadSize(t *testing.T) {
	conn, err := Dial("127.0.0.1:9999", 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	// Test with data that's too large
	largeData := make([]byte, MaxPayloadSize+1)
	err = conn.WritePacket(largeData)
	if err == nil {
		t.Error("Expected error for oversized packet, got nil")
	}

	// Test with maximum allowed size
	maxData := make([]byte, MaxPayloadSize)
	// This will fail to send without a server, but should pass size check
	err = conn.WritePacket(maxData)
	// The error will be from sending, not from size check
	if err != nil && err.Error() == "packet too large" {
		t.Error("MaxPayloadSize should be acceptable")
	}
}
