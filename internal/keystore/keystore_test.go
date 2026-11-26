package keystore

import (
	"errors"
	"testing"
)

// fake is an in-memory backend, so tests never touch the real registry or
// OS keychain.
func fake(store map[string]string) backend {
	return backend{
		get:    func() (string, error) { return store["key"], nil },
		set:    func(v string) error { store["key"] = v; return nil },
		remove: func() error { delete(store, "key"); return nil },
	}
}

func useFakes(t *testing.T) (plain, secure map[string]string) {
	t.Helper()
	savedSettings, savedKeychain := settings, keychain
	t.Cleanup(func() { settings, keychain = savedSettings, savedKeychain })
	plain, secure = map[string]string{}, map[string]string{}
	settings = fake(plain)
	chain := fake(secure)
	keychain = &chain
	t.Setenv("VT_API_KEY", "")
	return plain, secure
}

func TestSaveAndLoadAcrossBackends(t *testing.T) {
	plain, secure := useFakes(t)

	// Secure save writes to the keychain and clears any plaintext copy.
	plain["key"] = "old-plaintext"
	if where, err := SaveKey("secret1", true); where != "keychain" || err != nil {
		t.Fatalf("SaveKey = %q, %v", where, err)
	}
	if _, left := plain["key"]; secure["key"] != "secret1" || left {
		t.Errorf("keychain %q, plaintext left behind: %v", secure["key"], left)
	}
	if LoadKey() != "secret1" || !KeyInKeychain() {
		t.Errorf("LoadKey = %q, KeyInKeychain = %v", LoadKey(), KeyInKeychain())
	}

	// Plaintext save writes to settings and clears the keychain copy.
	if where, err := SaveKey("secret2", false); where != "settings" || err != nil {
		t.Fatalf("SaveKey = %q, %v", where, err)
	}
	if _, left := secure["key"]; plain["key"] != "secret2" || left {
		t.Errorf("settings %q, keychain copy left behind: %v", plain["key"], left)
	}
	if LoadKey() != "secret2" || KeyInKeychain() {
		t.Errorf("LoadKey = %q, KeyInKeychain = %v", LoadKey(), KeyInKeychain())
	}

	// The environment variable wins over both stores.
	secure["key"] = "in-keychain"
	t.Setenv("VT_API_KEY", "env-secret")
	if got := LoadKey(); got != "env-secret" {
		t.Errorf("LoadKey with env = %q", got)
	}
}

func TestKeychainPreferredOverSettingsWhenBothHold(t *testing.T) {
	plain, secure := useFakes(t)
	plain["key"], secure["key"] = "plain", "secure"
	if got := LoadKey(); got != "secure" {
		t.Errorf("LoadKey = %q", got)
	}
}

func TestSecureSaveWithoutKeychainIsAnError(t *testing.T) {
	plain, _ := useFakes(t)
	keychain = nil
	if where, err := SaveKey("x", true); err == nil || where != "" {
		t.Errorf("SaveKey = %q, %v; want an error, not silent plaintext", where, err)
	}
	if len(plain) != 0 || KeychainAvailable() || KeyInKeychain() {
		t.Error("nothing may be stored, and the keychain must report unavailable")
	}
	if where, err := SaveKey("x", false); where != "settings" || err != nil || LoadKey() != "x" {
		t.Errorf("plaintext save without a keychain: %q, %v", where, err)
	}
}

func TestBackendErrors(t *testing.T) {
	plain, _ := useFakes(t)
	boom := errors.New("backend refused")
	keychain.set = func(string) error { return boom }
	keychain.get = func() (string, error) { return "", boom }
	plain["key"] = "kept"
	if _, err := SaveKey("x", true); !errors.Is(err, boom) {
		t.Errorf("err = %v", err)
	}
	if plain["key"] != "kept" {
		t.Error("a failed secure save must not delete the plaintext copy")
	}
	// A failing keychain read falls through to settings.
	if got := LoadKey(); got != "kept" || KeyInKeychain() {
		t.Errorf("LoadKey = %q, KeyInKeychain = %v", got, KeyInKeychain())
	}
}
