package db

import (
	"database/sql"
	"os"
	"testing"
)

// TestSmokeDatabase checks the database the built exe wrote during
// scripts/smoke-gui.ps1; it is skipped otherwise.
func TestSmokeDatabase(t *testing.T) {
	path := os.Getenv("HASHHARVEST_SMOKE_DB")
	if path == "" {
		t.Skip("run by scripts/smoke-gui.ps1")
	}
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	var scans, files, hashes, skipped, rows, version int
	var types string
	err = conn.QueryRow(`select (select count(*) from scans),
		files_scanned, hashes_found, skipped_files, hash_types from scans`).Scan(&scans, &files, &hashes, &skipped, &types)
	if err != nil {
		t.Fatal(err)
	}
	if scans != 1 || files != 2 || hashes != 3 || skipped != 0 || types != "MD5,SHA1,SHA256,SHA512" {
		t.Errorf("stored scan: %d scans; files=%d hashes=%d skipped=%d types=%s", scans, files, hashes, skipped, types)
	}
	if err := conn.QueryRow(`select (select count(*) from hash_results), user_version
		from pragma_user_version`).Scan(&rows, &version); err != nil {
		t.Fatal(err)
	}
	if rows != 3 || version != SchemaVersion {
		t.Errorf("stored rows = %d, schema version = %d; want 3 and %d", rows, version, SchemaVersion)
	}
}
