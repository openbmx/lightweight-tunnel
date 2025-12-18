package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestManageServiceInstallCreatesUnitFile(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")
	if err := os.WriteFile(configPath, []byte(`{"mode":"server"}`), 0644); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	var executed [][]string
	runner := func(name string, args ...string) ([]byte, error) {
		executed = append(executed, append([]string{name}, args...))
		return []byte("ok"), nil
	}

	if err := manageServiceWithRunner("install", "my-tunnel", configPath, tmp, runner); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	unitFile := filepath.Join(tmp, "my-tunnel.service")
	data, err := os.ReadFile(unitFile)
	if err != nil {
		t.Fatalf("unit file missing: %v", err)
	}

	content := string(data)
	absConfig, err := filepath.Abs(configPath)
	if err != nil {
		t.Fatalf("failed to resolve absolute config path: %v", err)
	}
	if !strings.Contains(content, absConfig) {
		t.Fatalf("unit file does not reference config path: %s", content)
	}

	expected := [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", "my-tunnel.service"},
		{"systemctl", "start", "my-tunnel.service"},
	}
	if !reflect.DeepEqual(executed, expected) {
		t.Fatalf("unexpected commands: %+v", executed)
	}
}

func TestManageServiceNormalizesNames(t *testing.T) {
	var executed [][]string
	runner := func(name string, args ...string) ([]byte, error) {
		executed = append(executed, append([]string{name}, args...))
		return nil, nil
	}

	if err := manageServiceWithRunner("restart", "custom.service", "", t.TempDir(), runner); err != nil {
		t.Fatalf("restart failed: %v", err)
	}

	expected := [][]string{
		{"systemctl", "restart", "custom.service"},
	}
	if !reflect.DeepEqual(executed, expected) {
		t.Fatalf("unexpected commands: %+v", executed)
	}
}
