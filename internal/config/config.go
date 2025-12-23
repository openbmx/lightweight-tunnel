package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// Config holds the tunnel configuration
type Config struct {
	Mode               string   `json:"mode"`                 // "client" or "server"
	Transport          string   `json:"transport"`            // "rawtcp" only (true TCP disguise, requires root)
	LocalAddr          string   `json:"local_addr"`           // Local address to listen on
	RemoteAddr         string   `json:"remote_addr"`          // Remote address to connect to (client mode)
	TunnelAddr         string   `json:"tunnel_addr"`          // Tunnel network address (e.g., "10.0.0.1/24")
	MTU                int      `json:"mtu"`                  // MTU size (0 = auto-detect)
	FECDataShards      int      `json:"fec_data"`             // Number of FEC data shards
	FECParityShards    int      `json:"fec_parity"`           // Number of FEC parity shards
	Timeout            int      `json:"timeout"`              // Connection timeout in seconds
	KeepaliveInterval  int      `json:"keepalive"`            // Keepalive interval in seconds
	SendQueueSize      int      `json:"send_queue_size"`      // Size of send queue buffer (default 1000)
	RecvQueueSize      int      `json:"recv_queue_size"`      // Size of receive queue buffer (default 1000)
	Key                string   `json:"key"`                  // Encryption key for tunnel traffic (required for secure communication)
	TunName            string   `json:"tun_name"`             // Optional TUN device name (empty = auto)
	Routes             []string `json:"routes"`               // Additional routes to advertise to peers
	ConfigPushInterval int      `json:"config_push_interval"` // Interval (seconds) for server to push new config/key (0=disabled)
	MultiClient        bool     `json:"multi_client"`         // Enable multi-client support (server mode, default true)
	MaxClients         int      `json:"max_clients"`          // Maximum number of concurrent clients (default 100)
	ClientIsolation    bool     `json:"client_isolation"`     // Enable client isolation (clients cannot communicate with each other)

	// P2P and routing configuration
	P2PEnabled          bool `json:"p2p_enabled"`           // Enable P2P direct connections (default true)
	P2PPort             int  `json:"p2p_port"`              // UDP port for P2P connections (default 0 = auto)
	EnableMeshRouting   bool `json:"enable_mesh_routing"`   // Enable mesh routing through other clients (default true)
	MaxHops             int  `json:"max_hops"`              // Maximum hops for mesh routing (default 3)
	RouteUpdateInterval int  `json:"route_update_interval"` // Route quality check interval in seconds (default 30)
	P2PTimeout          int  `json:"p2p_timeout"`           // P2P connection timeout in seconds (default 5)
	EnableNATDetection  bool `json:"enable_nat_detection"`  // Enable automatic NAT type detection (default true)
	EnableXDP           bool `json:"enable_xdp"`            // Enable lightweight XDP/eBPF fast-path classification
	EnableKernelTune    bool `json:"enable_kernel_tune"`    // Apply kernel tunings (TFO/BBR2) on startup

	// On-demand P2P configuration
	RouteAdvertInterval  int `json:"route_advert_interval"`  // Route advertisement interval in seconds (default 300)
	P2PKeepAliveInterval int `json:"p2p_keepalive_interval"` // P2P keepalive interval in seconds (default 25)
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Mode:                 "server",
		Transport:            "rawtcp", // Fixed to rawtcp for true TCP disguise
		LocalAddr:            "0.0.0.0:9000",
		RemoteAddr:           "",
		TunnelAddr:           "10.0.0.1/24",
		MTU:                  1400,
		FECDataShards:        10,
		FECParityShards:      3,
		Timeout:              30,
		KeepaliveInterval:    10,
		SendQueueSize:        5000, // Increased from 1000 to prevent queue full errors
		RecvQueueSize:        5000, // Increased from 1000 to handle burst traffic
		TunName:              "",
		Routes:               []string{},
		ConfigPushInterval:   0,
		MultiClient:          true,
		MaxClients:           100,
		ClientIsolation:      false,
		P2PEnabled:           true,
		P2PPort:              0, // Auto-select
		EnableMeshRouting:    true,
		MaxHops:              3,
		RouteUpdateInterval:  30,
		P2PTimeout:           5,
		EnableNATDetection:   true,
		EnableXDP:            true,
		EnableKernelTune:     true,
		RouteAdvertInterval:  300, // 5 minutes
		P2PKeepAliveInterval: 25,  // 25 seconds
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
		config.SendQueueSize = 5000 // Increased default from 1000
	}
	if config.RecvQueueSize == 0 {
		config.RecvQueueSize = 5000 // Increased default from 1000
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
	if config.RouteAdvertInterval == 0 {
		config.RouteAdvertInterval = 300
	}
	if config.P2PKeepAliveInterval == 0 {
		config.P2PKeepAliveInterval = 25
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
	if _, exists := rawConfig["enable_nat_detection"]; !exists {
		config.EnableNATDetection = true
	}
	if _, exists := rawConfig["enable_xdp"]; !exists {
		config.EnableXDP = true
	}
	if _, exists := rawConfig["enable_kernel_tune"]; !exists {
		config.EnableKernelTune = true
	}

	return &config, nil
}

// SaveConfig saves configuration to a file
// Only saves essential fields for cleaner config files.
// Note: This function saves a minimal subset of configuration fields.
// Additional fields in config files are preserved on load but will be lost on save.
// To preserve all fields, modify the config file manually and avoid regenerating it.
func SaveConfig(filename string, config *Config) error {
	// Create a minimal config map with only essential fields
	minimalConfig := make(map[string]interface{})

	// Always include mode
	minimalConfig["mode"] = config.Mode

	// Server-specific fields
	if config.Mode == "server" {
		minimalConfig["local_addr"] = config.LocalAddr
	}

	// Client-specific fields
	if config.Mode == "client" {
		minimalConfig["remote_addr"] = config.RemoteAddr
	}

	// Common essential fields
	minimalConfig["tunnel_addr"] = config.TunnelAddr
	minimalConfig["key"] = config.Key
	minimalConfig["mtu"] = config.MTU
	minimalConfig["enable_nat_detection"] = config.EnableNATDetection
	minimalConfig["enable_xdp"] = config.EnableXDP
	minimalConfig["enable_kernel_tune"] = config.EnableKernelTune

	data, err := json.MarshalIndent(minimalConfig, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0600)
}

// UpdateConfigKey updates only the key field in an existing config file while preserving other fields.
func UpdateConfigKey(filename string, newKey string) error {
	if newKey == "" {
		return fmt.Errorf("new key is empty")
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF}) // Handle UTF-8 BOM

	var cfgMap map[string]interface{}
	if err := json.Unmarshal(data, &cfgMap); err != nil {
		return err
	}

	cfgMap["key"] = newKey

	updated, err := json.MarshalIndent(cfgMap, "", "  ")
	if err != nil {
		return err
	}

	info, err := os.Stat(filename)
	if err != nil {
		return err
	}

	origPerm := info.Mode().Perm()
	targetPerm := origPerm | 0o200 // ensure owner-write while updating
	restorePerm := origPerm != targetPerm

	if restorePerm {
		if err := os.Chmod(filename, targetPerm); err != nil {
			return fmt.Errorf("failed to enable write permission on %s: %w", filename, err)
		}
	}

	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_TRUNC, 0)
	writeErr := err
	if writeErr == nil {
		if _, err := f.Write(updated); err != nil {
			writeErr = err
		}
		if cerr := f.Close(); writeErr == nil && cerr != nil {
			writeErr = cerr
		}
	}

	if writeErr != nil {
		if restorePerm {
			if restoreErr := os.Chmod(filename, origPerm); restoreErr != nil {
				return fmt.Errorf("update config: %w; failed to restore permissions on %s: %w", writeErr, filename, restoreErr)
			}
		}
		return writeErr
	}

	if restorePerm {
		if err := os.Chmod(filename, origPerm); err != nil {
			return fmt.Errorf("failed to restore permissions on %s: %w", filename, err)
		}
	}

	return nil
}
