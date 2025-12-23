package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestUpdateConfigKeyPreservesModeAndUpdatesKey(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.json")

	initial := []byte(`{"mode":"server","key":"old-key","mtu":1400}`)
	if err := os.WriteFile(path, initial, 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	// Simulate a locked-down config file (read-only for owner).
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatalf("chmod temp config: %v", err)
	}

	origMode := filePerm(t, path)

	if err := UpdateConfigKey(path, "new-key"); err != nil {
		t.Fatalf("UpdateConfigKey returned error: %v", err)
	}

	// Verify the key was updated.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read updated config: %v", err)
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal updated config: %v", err)
	}
	if cfg["key"] != "new-key" {
		t.Fatalf("expected key to be updated to new-key, got %v", cfg["key"])
	}

	// Original permissions should be restored after the write.
	if mode := filePerm(t, path); mode != origMode {
		t.Fatalf("expected mode %v to be restored, got %v", origMode, mode)
	}
}

func filePerm(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Mode().Perm()
}
