package config

import (
	"encoding/json"
	"os"
)

// Config holds the tunnel configuration
type Config struct {
	Mode          string `json:"mode"`           // "client" or "server"
	LocalAddr     string `json:"local_addr"`     // Local address to listen on
	RemoteAddr    string `json:"remote_addr"`    // Remote address to connect to (client mode)
	TunnelAddr    string `json:"tunnel_addr"`    // Tunnel network address (e.g., "10.0.0.1/24")
	MTU           int    `json:"mtu"`            // MTU size
	FECDataShards int    `json:"fec_data"`       // Number of FEC data shards
	FECParityShards int  `json:"fec_parity"`     // Number of FEC parity shards
	Timeout       int    `json:"timeout"`        // Connection timeout in seconds
	KeepaliveInterval int `json:"keepalive"`    // Keepalive interval in seconds
	SendQueueSize int    `json:"send_queue_size"` // Size of send queue buffer (default 1000)
	RecvQueueSize int    `json:"recv_queue_size"` // Size of receive queue buffer (default 1000)
	TLSEnabled    bool   `json:"tls_enabled"`    // Enable TLS encryption
	TLSCertFile   string `json:"tls_cert_file"`  // Path to TLS certificate file (server mode)
	TLSKeyFile    string `json:"tls_key_file"`   // Path to TLS private key file (server mode)
	TLSSkipVerify bool   `json:"tls_skip_verify"` // Skip TLS certificate verification (client mode, insecure)
	MultiClient   bool   `json:"multi_client"`   // Enable multi-client support (server mode, default true)
	MaxClients    int    `json:"max_clients"`    // Maximum number of concurrent clients (default 100)
	ClientIsolation bool `json:"client_isolation"` // Enable client isolation (clients cannot communicate with each other)
	
	// P2P and routing configuration
	P2PEnabled         bool   `json:"p2p_enabled"`          // Enable P2P direct connections (default true)
	P2PPort            int    `json:"p2p_port"`             // UDP port for P2P connections (default 0 = auto)
	EnableMeshRouting  bool   `json:"enable_mesh_routing"`  // Enable mesh routing through other clients (default true)
	MaxHops            int    `json:"max_hops"`             // Maximum hops for mesh routing (default 3)
	RouteUpdateInterval int   `json:"route_update_interval"` // Route quality check interval in seconds (default 30)
	P2PTimeout         int    `json:"p2p_timeout"`          // P2P connection timeout in seconds (default 5)
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Mode:              "server",
		LocalAddr:         "0.0.0.0:9000",
		RemoteAddr:        "",
		TunnelAddr:        "10.0.0.1/24",
		MTU:               1400,
		FECDataShards:     10,
		FECParityShards:   3,
		Timeout:           30,
		KeepaliveInterval: 10,
		SendQueueSize:     1000,
		RecvQueueSize:     1000,
		MultiClient:         true,
		MaxClients:          100,
		ClientIsolation:     false,
		P2PEnabled:          true,
		P2PPort:             0,  // Auto-select
		EnableMeshRouting:   true,
		MaxHops:             3,
		RouteUpdateInterval: 30,
		P2PTimeout:          5,
	}
}

// LoadConfig loads configuration from a file
func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// First unmarshal to a map to check which fields are explicitly set
	var rawConfig map[string]interface{}
	if err := json.Unmarshal(data, &rawConfig); err != nil {
		return nil, err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	// Set defaults for missing fields
	if config.MTU == 0 {
		config.MTU = 1400
	}
	if config.FECDataShards == 0 {
		config.FECDataShards = 10
	}
	if config.FECParityShards == 0 {
		config.FECParityShards = 3
	}
	if config.Timeout == 0 {
		config.Timeout = 30
	}
	if config.KeepaliveInterval == 0 {
		config.KeepaliveInterval = 10
	}
	if config.SendQueueSize == 0 {
		config.SendQueueSize = 1000
	}
	if config.RecvQueueSize == 0 {
		config.RecvQueueSize = 1000
	}
	if config.MaxClients == 0 {
		config.MaxClients = 100
	}
	if config.MaxHops == 0 {
		config.MaxHops = 3
	}
	if config.RouteUpdateInterval == 0 {
		config.RouteUpdateInterval = 30
	}
	if config.P2PTimeout == 0 {
		config.P2PTimeout = 5
	}
	
	// Default multi_client to true for server mode if not explicitly set
	// This matches the command-line default and expected behavior
	if config.Mode == "server" {
		if _, exists := rawConfig["multi_client"]; !exists {
			config.MultiClient = true
		}
	}
	
	// Default P2P and mesh routing to true if not explicitly set
	if _, exists := rawConfig["p2p_enabled"]; !exists {
		config.P2PEnabled = true
	}
	if _, exists := rawConfig["enable_mesh_routing"]; !exists {
		config.EnableMeshRouting = true
	}

	return &config, nil
}

// SaveConfig saves configuration to a file
func SaveConfig(filename string, config *Config) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}
