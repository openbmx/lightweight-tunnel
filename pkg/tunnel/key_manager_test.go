package tunnel

import (
	"testing"
	"time"

	"github.com/C018/lightweight-tunnel/pkg/crypto"
)

func TestKeyManagerRotationActivation(t *testing.T) {
	km, err := newKeyManager("old-key")
	if err != nil {
		t.Fatalf("unexpected error creating key manager: %v", err)
	}

	if !km.hasCipher() || km.activeVersion() != 1 {
		t.Fatalf("expected initial key version 1 to be active")
	}

	version, err := km.preparePendingKey("new-key", 0)
	if err != nil {
		t.Fatalf("unexpected error preparing pending key: %v", err)
	}
	if version != 2 {
		t.Fatalf("expected pending version 2, got %d", version)
	}

	newKey, ok := km.activatePending(version, time.Second)
	if !ok {
		t.Fatalf("pending key was not activated")
	}
	if newKey != "new-key" {
		t.Fatalf("unexpected activated key returned: %s", newKey)
	}

	// Current key should decrypt normally
	currentCipher, _ := crypto.NewCipher("new-key")
	ciphertext, _ := currentCipher.Encrypt([]byte("payload"))
	if _, err := km.decrypt(ciphertext); err != nil {
		t.Fatalf("expected decrypt with active key to succeed: %v", err)
	}

	// Previous key should still be accepted before grace expires
	oldCipher, _ := crypto.NewCipher("old-key")
	oldCiphertext, _ := oldCipher.Encrypt([]byte("legacy"))
	if _, err := km.decrypt(oldCiphertext); err != nil {
		t.Fatalf("expected decrypt with previous key during grace to succeed: %v", err)
	}

	// Wait for grace window to expire and ensure old key is rejected
	time.Sleep(1100 * time.Millisecond)
	if _, err := km.decrypt(oldCiphertext); err == nil {
		t.Fatalf("expected decrypt with expired previous key to fail")
	}
}

func TestKeyManagerRejectsStaleVersion(t *testing.T) {
	km, err := newKeyManager("old-key")
	if err != nil {
		t.Fatalf("unexpected error creating key manager: %v", err)
	}

	if _, err := km.preparePendingKey("stale", km.activeVersion()); err == nil {
		t.Fatalf("expected stale version to be rejected")
	}
}
