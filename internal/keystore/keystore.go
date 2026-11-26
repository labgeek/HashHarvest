// Package keystore stores the VirusTotal API key in one of two places:
//
//   - the OS keychain (Windows Credential Manager), encrypted at rest, opt-in;
//   - plaintext settings (the Windows registry), the default.
//
// Reading prefers the VT_API_KEY environment variable, then the keychain,
// then settings. Writing goes to the backend the caller selects and removes
// the copy in the other, so the key lives in exactly one place.
//
// On Windows the registry value and credential names match those used by
// earlier releases, so an already saved key is still found.
package keystore

import (
	"errors"
	"os"
)

const (
	// service is also the registry organization and application that keys
	// saved by earlier releases are stored under.
	service = "HashHarvest"
	keyName = "vt_api_key"
)

// backend is one storage location. get returns "" when nothing is stored.
type backend struct {
	get    func() (string, error)
	set    func(string) error
	remove func() error
}

// settings and keychain are assigned per platform; keychain is nil where no
// OS keychain is supported. Tests replace them with in-memory fakes.
var (
	settings backend
	keychain *backend
)

// KeychainAvailable reports whether encrypted storage can be used.
func KeychainAvailable() bool { return keychain != nil }

// KeyInKeychain reports whether a key is currently stored in the keychain.
func KeyInKeychain() bool {
	if keychain == nil {
		return false
	}
	value, err := keychain.get()
	return err == nil && value != ""
}

// LoadKey returns the key from the environment, keychain, or settings
// ("" if none).
func LoadKey() string {
	if env := os.Getenv("VT_API_KEY"); env != "" {
		return env
	}
	if keychain != nil {
		if value, err := keychain.get(); err == nil && value != "" {
			return value
		}
	}
	value, _ := settings.get()
	return value
}

// SaveKey persists apiKey to the keychain (secure) or to plaintext settings
// and removes any copy from the other backend. It returns "keychain" or
// "settings". Requesting secure storage without a keychain is an error, not
// a silent fallback to plaintext.
func SaveKey(apiKey string, secure bool) (string, error) {
	if secure {
		if keychain == nil {
			return "", errors.New("No OS keychain backend is available on this platform; use plaintext storage.")
		}
		if err := keychain.set(apiKey); err != nil {
			return "", err
		}
		settings.remove() // best effort: drop any plaintext copy left behind
		return "keychain", nil
	}
	if err := settings.set(apiKey); err != nil {
		return "", err
	}
	if keychain != nil {
		keychain.remove() // best effort: nothing stored, or the backend refused
	}
	return "settings", nil
}
