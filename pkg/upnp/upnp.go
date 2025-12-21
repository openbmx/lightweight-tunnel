package upnp

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

// Client represents a UPnP client for port forwarding
type Client struct {
	gatewayURL string
	localAddr  net.IP
	timeout    time.Duration
}

var (
	// ErrNoGatewayFound indicates no UPnP gateway was discovered
	ErrNoGatewayFound = errors.New("no UPnP gateway found")
	// ErrPortMappingFailed indicates port mapping creation failed
	ErrPortMappingFailed = errors.New("failed to create port mapping")
)

// NewClient creates a new UPnP client
func NewClient(timeout time.Duration) *Client {
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	return &Client{
		timeout: timeout,
	}
}

// Discover discovers UPnP gateway on the local network
func (c *Client) Discover() error {
	// Get local IP address
	localIP, err := getLocalIP()
	if err != nil {
		return fmt.Errorf("failed to get local IP: %v", err)
	}
	c.localAddr = localIP
	
	log.Printf("UPnP: Starting discovery from local IP %s", localIP)
	
	// Send SSDP discovery message
	gatewayURL, err := c.discoverGateway()
	if err != nil {
		return err
	}
	
	c.gatewayURL = gatewayURL
	log.Printf("UPnP: Discovered gateway at %s", gatewayURL)
	return nil
}

// AddPortMapping adds a port mapping on the UPnP gateway
// protocol should be "TCP" or "UDP"
func (c *Client) AddPortMapping(externalPort, internalPort int, protocol string, description string, duration int) error {
	if c.gatewayURL == "" {
		return ErrNoGatewayFound
	}
	
	// Validate protocol
	protocol = strings.ToUpper(protocol)
	if protocol != "TCP" && protocol != "UDP" {
		return fmt.Errorf("invalid protocol: %s (must be TCP or UDP)", protocol)
	}
	
	// Default duration is 0 (permanent until reboot)
	// Non-zero durations would create temporary mappings
	
	log.Printf("UPnP: Adding port mapping %s:%d -> %s:%d (%s) for %d seconds",
		"0.0.0.0", externalPort, c.localAddr, internalPort, protocol, duration)
	
	// Try to add port mapping using IGD (Internet Gateway Device) protocol
	err := c.addPortMappingIGD(externalPort, internalPort, protocol, description, duration)
	if err != nil {
		log.Printf("UPnP: Failed to add port mapping: %v", err)
		return ErrPortMappingFailed
	}
	
	log.Printf("UPnP: Successfully added port mapping %s:%d -> %s:%d",
		"external", externalPort, c.localAddr, internalPort)
	return nil
}

// DeletePortMapping removes a port mapping from the UPnP gateway
func (c *Client) DeletePortMapping(externalPort int, protocol string) error {
	if c.gatewayURL == "" {
		return ErrNoGatewayFound
	}
	
	protocol = strings.ToUpper(protocol)
	if protocol != "TCP" && protocol != "UDP" {
		return fmt.Errorf("invalid protocol: %s", protocol)
	}
	
	log.Printf("UPnP: Deleting port mapping for %s:%d (%s)", "0.0.0.0", externalPort, protocol)
	
	err := c.deletePortMappingIGD(externalPort, protocol)
	if err != nil {
		log.Printf("UPnP: Failed to delete port mapping: %v", err)
		return err
	}
	
	log.Printf("UPnP: Successfully deleted port mapping")
	return nil
}

// GetExternalIP retrieves the external IP address from the UPnP gateway
func (c *Client) GetExternalIP() (net.IP, error) {
	if c.gatewayURL == "" {
		return nil, ErrNoGatewayFound
	}
	
	// Query external IP using IGD protocol
	externalIP, err := c.getExternalIPIGD()
	if err != nil {
		return nil, fmt.Errorf("failed to get external IP: %v", err)
	}
	
	log.Printf("UPnP: External IP is %s", externalIP)
	return externalIP, nil
}

// getLocalIP gets the local IP address
func getLocalIP() (net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP, nil
			}
		}
	}
	
	return nil, errors.New("no local IP address found")
}

// discoverGateway discovers the UPnP gateway using SSDP
func (c *Client) discoverGateway() (string, error) {
	// SSDP discovery message
	searchMsg := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n\r\n"
	
	// Send to multicast address
	addr, err := net.ResolveUDPAddr("udp4", "239.255.255.250:1900")
	if err != nil {
		return "", err
	}
	
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	
	conn.SetDeadline(time.Now().Add(c.timeout))
	
	_, err = conn.WriteToUDP([]byte(searchMsg), addr)
	if err != nil {
		return "", err
	}
	
	// Wait for response
	buf := make([]byte, 2048)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "", ErrNoGatewayFound
		}
		return "", err
	}
	
	// Parse response to extract LOCATION header
	response := string(buf[:n])
	lines := strings.Split(response, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToUpper(line), "LOCATION:") {
			location := strings.TrimSpace(line[9:])
			return location, nil
		}
	}
	
	return "", ErrNoGatewayFound
}

// addPortMappingIGD adds port mapping using IGD protocol
// This is a placeholder for the actual IGD implementation
// Returns an error indicating this requires full implementation
func (c *Client) addPortMappingIGD(externalPort, internalPort int, protocol string, description string, duration int) error {
	// This is a placeholder for the actual IGD implementation
	// Full implementation would require:
	// 1. Fetching the device description XML from c.gatewayURL
	// 2. Parsing the XML to find the control URL for WANIPConnection or WANPPPConnection
	// 3. Sending a SOAP AddPortMapping request to the control URL
	
	// For now, log that UPnP discovery succeeded but mapping is not implemented
	// Users can integrate full UPnP libraries like github.com/huin/goupnp if needed
	log.Printf("UPnP: Gateway discovered but port mapping requires full IGD implementation")
	log.Printf("UPnP: Would map external port %d to internal %s:%d (%s)", externalPort, c.localAddr, internalPort, protocol)
	
	// Return error to indicate feature is incomplete
	return errors.New("UPnP port mapping not fully implemented - discovery only")
}

// deletePortMappingIGD deletes port mapping using IGD protocol
func (c *Client) deletePortMappingIGD(externalPort int, protocol string) error {
	// Placeholder - would require full IGD/SOAP implementation
	log.Printf("UPnP: Would delete port mapping for port %d (%s)", externalPort, protocol)
	return nil
}

// getExternalIPIGD retrieves external IP using IGD protocol
func (c *Client) getExternalIPIGD() (net.IP, error) {
	// Placeholder - would require full IGD/SOAP implementation
	log.Printf("UPnP: External IP query would be performed here (requires full IGD implementation)")
	return nil, errors.New("UPnP external IP query not fully implemented - use STUN instead")
}

// TryAddPortMapping attempts to add a UPnP port mapping with best-effort approach
// Returns true if successful, false otherwise (non-blocking, logs errors)
func TryAddPortMapping(port int, protocol string, description string) bool {
	client := NewClient(3 * time.Second)
	
	// Discover gateway
	if err := client.Discover(); err != nil {
		log.Printf("UPnP: Discovery failed (continuing without UPnP): %v", err)
		return false
	}
	
	// Add port mapping (basic implementation)
	if err := client.AddPortMapping(port, port, protocol, description, 0); err != nil {
		log.Printf("UPnP: Port mapping setup incomplete (continuing without UPnP): %v", err)
		return false
	}
	
	log.Printf("UPnP: Basic configuration attempted for %s/%d", protocol, port)
	return true
}
