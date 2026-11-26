package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/labgeek/HashHarvest/internal/extractor"
)

// TestSampleEvidence scans samples/evidence and requires exactly the rows
// in samples/expected.json, which were computed independently of this code.
// It keeps the shipped demo accurate and covers every supported format.
func TestSampleEvidence(t *testing.T) {
	samples := filepath.Join("..", "..", "samples")
	type row struct {
		File      string `json:"file"`
		HashType  string `json:"hash_type"`
		HashValue string `json:"hash_value"`
	}
	var want struct {
		Results       []row    `json:"results"`
		Skipped       []string `json:"skipped"`
		WatchlistHits int      `json:"watchlist_hits"`
	}
	raw, err := os.ReadFile(filepath.Join(samples, "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}

	root := filepath.Join(samples, "evidence")
	rel := func(path string) string {
		r, err := filepath.Rel(root, path)
		if err != nil {
			t.Fatal(err)
		}
		return filepath.ToSlash(r)
	}
	result := scan(t, Scanner{Mode: "text"}, root, nil)

	var got []row
	for path, hits := range result.Results {
		for _, h := range hits {
			got = append(got, row{rel(path), h.HashType, h.HashValue})
		}
	}
	sort.Slice(got, func(i, j int) bool {
		a, b := got[i], got[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.HashType != b.HashType {
			return a.HashType < b.HashType
		}
		return a.HashValue < b.HashValue
	})
	if !reflect.DeepEqual(got, want.Results) {
		t.Errorf("results:\n got %v\nwant %v", got, want.Results)
	}

	var skipped []string
	for _, e := range result.Errors {
		skipped = append(skipped, rel(e.Path))
	}
	if !reflect.DeepEqual(skipped, want.Skipped) {
		t.Errorf("skipped = %v, want %v", skipped, want.Skipped)
	}

	list, err := os.ReadFile(filepath.Join(samples, "watchlist.txt"))
	if err != nil {
		t.Fatal(err)
	}
	watched := map[string]bool{}
	for _, h := range extractor.HashSet(string(list)) {
		watched[h] = true
	}
	hits := 0
	for _, r := range got {
		if watched[r.HashValue] {
			hits++
		}
	}
	if len(watched) != 3 || hits != want.WatchlistHits {
		t.Errorf("watchlist: %d entries, %d hits; want 3 and %d", len(watched), hits, want.WatchlistHits)
	}
}
