package tunnel

import (
	"errors"
	"sync"
	"time"

	"github.com/C018/lightweight-tunnel/pkg/crypto"
)

type keyManager struct {
	mu              sync.RWMutex
	current         *crypto.Cipher
	pending         *crypto.Cipher
	previous        *crypto.Cipher
	currentVersion  int
	pendingVersion  int
	previousExpiry  time.Time
	pendingReadyKey string
}

func newKeyManager(key string) (*keyManager, error) {
	km := &keyManager{}
	if key == "" {
		return km, nil
	}

	c, err := crypto.NewCipher(key)
	if err != nil {
		return nil, err
	}
	km.current = c
	km.currentVersion = 1
	return km, nil
}

func (k *keyManager) hasCipher() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.current != nil
}

func (k *keyManager) activeVersion() int {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.currentVersion
}

func (k *keyManager) pendingVersionValue() int {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.pendingVersion
}

func (k *keyManager) encrypt(data []byte) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if k.current == nil {
		return data, nil
	}
	return k.current.Encrypt(data)
}

func (k *keyManager) decrypt(data []byte) ([]byte, error) {
	k.expirePrevious()

	k.mu.RLock()
	current := k.current
	pending := k.pending
	previous := k.previous
	prevExpiry := k.previousExpiry
	k.mu.RUnlock()

	candidates := []struct {
		cipher *crypto.Cipher
		valid  bool
	}{
		{current, current != nil},
		{pending, pending != nil},
		{previous, previous != nil && (prevExpiry.IsZero() || time.Now().Before(prevExpiry))},
	}

	var lastErr error
	for _, cand := range candidates {
		if !cand.valid {
			continue
		}
		plain, err := cand.cipher.Decrypt(data)
		if err == nil {
			return plain, nil
		}
		lastErr = err
	}

	if lastErr == nil {
		lastErr = errors.New("no cipher available")
	}
	return nil, lastErr
}

func (k *keyManager) expirePrevious() {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.previous != nil && !k.previousExpiry.IsZero() && time.Now().After(k.previousExpiry) {
		k.previous = nil
		k.previousExpiry = time.Time{}
	}
}

func (k *keyManager) preparePendingKey(key string, version int) (int, error) {
	if key == "" {
		return 0, errors.New("pending key cannot be empty")
	}

	c, err := crypto.NewCipher(key)
	if err != nil {
		return 0, err
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	if version <= 0 {
		if k.currentVersion == 0 {
			version = 1
		} else {
			version = k.currentVersion + 1
		}
	}

	if version <= k.currentVersion || (k.pending != nil && version <= k.pendingVersion) {
		return 0, errors.New("stale key version")
	}

	k.pending = c
	k.pendingVersion = version
	k.pendingReadyKey = key
	return version, nil
}

func (k *keyManager) activatePending(version int, grace time.Duration) (string, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.pending == nil {
		return "", false
	}
	if version > 0 && version != k.pendingVersion {
		return "", false
	}

	if grace < 0 {
		grace = 0
	}

	k.previous = k.current
	if k.previous != nil {
		k.previousExpiry = time.Now().Add(grace)
	} else {
		k.previousExpiry = time.Time{}
	}

	k.current = k.pending
	k.currentVersion = k.pendingVersion
	newKey := k.pendingReadyKey
	k.pending = nil
	k.pendingVersion = 0
	k.pendingReadyKey = ""
	return newKey, true
}

func (k *keyManager) previousTTL() time.Duration {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if k.previous == nil || k.previousExpiry.IsZero() {
		return 0
	}
	return time.Until(k.previousExpiry)
}
