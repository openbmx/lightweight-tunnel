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
		MultiClient:       true,
		MaxClients:        100,
		ClientIsolation:   false,
	}
}

// LoadConfig loads configuration from a file
func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
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
	// Note: MultiClient and ClientIsolation default to false when loaded from JSON
	// The command-line interface and DefaultConfig() set MultiClient=true by default
	// Explicitly set "multi_client": true in JSON config for multi-client support

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
