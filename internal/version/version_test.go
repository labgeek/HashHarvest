package version

import (
	"encoding/json"
	"os"
	"regexp"
	"testing"
)

func TestWailsConfigMatchesVersion(t *testing.T) {
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(Version) {
		t.Errorf("Version %q is not MAJOR.MINOR.PATCH", Version)
	}
	data, err := os.ReadFile("../../wails.json")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Info struct {
			ProductVersion string `json:"productVersion"`
		} `json:"info"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Info.ProductVersion != Version {
		t.Errorf("wails.json productVersion %q, want %q", cfg.Info.ProductVersion, Version)
	}
}
