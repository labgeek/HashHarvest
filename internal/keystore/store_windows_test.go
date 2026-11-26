//go:build windows

package keystore

import (
	"os"
	"os/exec"
	"testing"
)

// These tests write to the real registry and Credential Manager, under
// names used only by tests, so they are opt-in:
//
//	HASHHARVEST_OS_STORE_TEST=1 go test ./internal/keystore/

const (
	testService = "HashHarvestGoTest"
	testUser    = "probe"
)

func requireOptIn(t *testing.T) {
	if os.Getenv("HASHHARVEST_OS_STORE_TEST") == "" {
		t.Skip("set HASHHARVEST_OS_STORE_TEST=1 to exercise the real registry and Credential Manager")
	}
}

func TestRegistryRoundTrip(t *testing.T) {
	requireOptIn(t)
	const path, name = `Software\` + testService + `\` + testService, "vt_api_key"
	t.Cleanup(func() {
		regDelete(path, name)
		exec.Command("reg", "delete", `HKCU\Software\`+testService, "/f").Run() // drop the empty test keys
	})

	if got, err := regGet(path, name); got != "" || err != nil {
		t.Fatalf("before set: %q, %v", got, err)
	}
	for _, value := range []string{"plain-key-123", "unicode é中", ""} {
		if err := regSet(path, name, value); err != nil {
			t.Fatal(err)
		}
		if got, err := regGet(path, name); got != value || err != nil {
			t.Errorf("regGet = %q, %v; want %q", got, err, value)
		}
	}
	if err := regDelete(path, name); err != nil {
		t.Fatal(err)
	}
	if err := regDelete(path, name); err != nil {
		t.Errorf("deleting a missing value must not fail: %v", err)
	}
	if got, _ := regGet(path, name); got != "" {
		t.Errorf("after delete: %q", got)
	}
}

func TestCredentialRoundTrip(t *testing.T) {
	requireOptIn(t)
	t.Cleanup(func() { credRemove(testService, testUser) })

	if got, err := credGet(testService, testUser); got != "" || err != nil {
		t.Fatalf("before set: %q, %v", got, err)
	}
	for _, secret := range []string{"secret-1", "unicode é\U0001F642"} {
		if err := credWrite(testService, testUser, secret); err != nil {
			t.Fatal(err)
		}
		if got, err := credGet(testService, testUser); got != secret || err != nil {
			t.Errorf("credGet = %q, %v; want %q", got, err, secret)
		}
	}
	if got, _ := credGet(testService, "someone-else"); got != "" {
		t.Errorf("another user's lookup returned %q", got)
	}
	if err := credRemove(testService, testUser); err != nil {
		t.Fatal(err)
	}
	if got, _ := credGet(testService, testUser); got != "" {
		t.Errorf("after remove: %q", got)
	}
}
