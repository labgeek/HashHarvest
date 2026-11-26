//go:build !windows

package keystore

// Non-Windows fallback. HashHarvest's supported platform is Windows; this
// keeps the package buildable and usable elsewhere.
//
// ponytail: plaintext settings live in <config dir>/HashHarvest/HashHarvest.conf
// in the INI layout Qt writes on Linux, and there is no OS keychain backend
// (the "encrypted" option is disabled). Add macOS Keychain / Secret Service
// support here if those platforms become targets.

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func init() {
	settings = backend{get: fileGet, set: fileSet, remove: fileRemove}
}

func settingsFile() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, service, service+".conf"), nil
}

func fileGet() (string, error) {
	path, err := settingsFile()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), keyName+"="); ok {
			return value, nil
		}
	}
	return "", nil
}

func fileSet(value string) error {
	path, err := settingsFile()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte("[General]\n"+keyName+"="+value+"\n"), 0o600)
}

func fileRemove() error {
	path, err := settingsFile()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
