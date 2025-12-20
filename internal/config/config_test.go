package config

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestLoadConfigMultiClientDefault(t *testing.T) {
	// Create a temporary config file without multi_client field
	tmpFile, err := os.CreateTemp("", "test_config_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write a server config without multi_client field
	configData := `{
  "mode": "server",
  "local_addr": "0.0.0.0:9000",
  "tunnel_addr": "10.0.0.1/24"
}`
	if _, err := tmpFile.WriteString(configData); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	tmpFile.Close()

	// Load the config
	cfg, err := LoadConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify multi_client defaults to true for server mode
	if !cfg.MultiClient {
		t.Errorf("Expected MultiClient to default to true, got false")
	}

	// Verify MaxClients defaults to 100
	if cfg.MaxClients != 100 {
		t.Errorf("Expected MaxClients to be 100, got %d", cfg.MaxClients)
	}
}

func TestLoadConfigMultiClientExplicitFalse(t *testing.T) {
	// Create a temporary config file with explicit multi_client = false
	tmpFile, err := os.CreateTemp("", "test_config_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write a server config with explicit multi_client = false
	configData := `{
  "mode": "server",
  "local_addr": "0.0.0.0:9000",
  "tunnel_addr": "10.0.0.1/24",
  "multi_client": false
}`
	if _, err := tmpFile.WriteString(configData); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	tmpFile.Close()

	// Load the config
	cfg, err := LoadConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify multi_client respects explicit false value
	if cfg.MultiClient {
		t.Errorf("Expected MultiClient to be false when explicitly set, got true")
	}
}

func TestLoadConfigMultiClientExplicitTrue(t *testing.T) {
	// Create a temporary config file with explicit multi_client = true
	tmpFile, err := os.CreateTemp("", "test_config_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write a server config with explicit multi_client = true
	configData := `{
  "mode": "server",
  "local_addr": "0.0.0.0:9000",
  "tunnel_addr": "10.0.0.1/24",
  "multi_client": true
}`
	if _, err := tmpFile.WriteString(configData); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	tmpFile.Close()

	// Load the config
	cfg, err := LoadConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify multi_client is true
	if !cfg.MultiClient {
		t.Errorf("Expected MultiClient to be true, got false")
	}
}

func TestLoadConfigClientModeNoDefault(t *testing.T) {
	// Create a temporary config file for client mode without multi_client
	tmpFile, err := os.CreateTemp("", "test_config_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write a client config without multi_client field
	configData := `{
  "mode": "client",
  "local_addr": "0.0.0.0:9000",
  "remote_addr": "192.168.1.1:9000",
  "tunnel_addr": "10.0.0.2/24"
}`
	if _, err := tmpFile.WriteString(configData); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}
	tmpFile.Close()

	// Load the config
	cfg, err := LoadConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify multi_client remains false for client mode (not set to true)
	// Client mode doesn't use multi_client, so it should remain false
	if cfg.MultiClient {
		t.Errorf("Expected MultiClient to remain false for client mode, got true")
	}
}

func TestUpdateConfigKeyHandlesBOM(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test_config_bom_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	original := `{
  "mode": "server",
  "local_addr": "0.0.0.0:9000",
  "tunnel_addr": "10.0.0.1/24",
  "key": "old-key-value"
}`
	bomPrefixed := append([]byte{0xEF, 0xBB, 0xBF}, []byte(original)...)

	if err := os.WriteFile(tmpFile.Name(), bomPrefixed, 0644); err != nil {
		t.Fatalf("Failed to write config with BOM: %v", err)
	}

	newKey := "new-rotated-key-123456"
	if err := UpdateConfigKey(tmpFile.Name(), newKey); err != nil {
		t.Fatalf("UpdateConfigKey failed: %v", err)
	}

	updated, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to read updated config: %v", err)
	}

	if bytes.HasPrefix(updated, []byte{0xEF, 0xBB, 0xBF}) {
		t.Fatalf("Expected BOM to be stripped before writing updated config")
	}

	var cfg Config
	if err := json.Unmarshal(updated, &cfg); err != nil {
		t.Fatalf("Failed to unmarshal updated config: %v", err)
	}

	if cfg.Key != newKey {
		t.Fatalf("Expected key to be updated to %s, got %s", newKey, cfg.Key)
	}
	if cfg.Mode != "server" || cfg.TunnelAddr != "10.0.0.1/24" {
		t.Fatalf("Expected other fields to be preserved, got mode=%s tunnel_addr=%s", cfg.Mode, cfg.TunnelAddr)
	}
}
