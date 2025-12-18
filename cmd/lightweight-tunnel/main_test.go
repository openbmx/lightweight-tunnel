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

	originalDir := serviceDir
	serviceDir = tmp
	defer func() { serviceDir = originalDir }()

	var executed [][]string
	originalRunner := runCommand
	runCommand = func(name string, args ...string) ([]byte, error) {
		executed = append(executed, append([]string{name}, args...))
		return []byte("ok"), nil
	}
	defer func() { runCommand = originalRunner }()

	if err := manageService("install", "my-tunnel", configPath); err != nil {
		t.Fatalf("install failed: %v", err)
	}

	unitFile := filepath.Join(tmp, "my-tunnel.service")
	data, err := os.ReadFile(unitFile)
	if err != nil {
		t.Fatalf("unit file missing: %v", err)
	}

	content := string(data)
	absConfig, _ := filepath.Abs(configPath)
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
	originalRunner := runCommand
	runCommand = func(name string, args ...string) ([]byte, error) {
		executed = append(executed, append([]string{name}, args...))
		return nil, nil
	}
	defer func() { runCommand = originalRunner }()

	if err := manageService("restart", "custom.service", ""); err != nil {
		t.Fatalf("restart failed: %v", err)
	}

	expected := [][]string{
		{"systemctl", "restart", "custom.service"},
	}
	if !reflect.DeepEqual(executed, expected) {
		t.Fatalf("unexpected commands: %+v", executed)
	}
}
