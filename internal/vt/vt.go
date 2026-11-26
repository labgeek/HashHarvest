// Package vt looks hashes up on VirusTotal. It talks
// to the v3 REST API directly with net/http.
package vt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
)

// BaseURL is the API root; tests point it at a local server.
var BaseURL = "https://www.virustotal.com/api/v3"

// vt-py's default request timeout.
var client = &http.Client{Timeout: 300 * time.Second}

// Verdict is the outcome for one hash: "malicious", "suspicious", "clean",
// "not found", "n/a", or "error", with a short detail string.
type Verdict struct {
	Verdict string
	Detail  string
}

// VerdictFromStats reduces VirusTotal's last_analysis_stats to a verdict
// and a "hits/total" detail.
func VerdictFromStats(stats map[string]int) (verdict, detail string) {
	total := 0
	for _, n := range stats {
		total += n
	}
	if n := stats["malicious"]; n != 0 {
		return "malicious", fmt.Sprintf("%d/%d", n, total)
	}
	if n := stats["suspicious"]; n != 0 {
		return "suspicious", fmt.Sprintf("%d/%d", n, total)
	}
	return "clean", fmt.Sprintf("0/%d", total)
}

// LookupHashes looks each hash up, in order, after lowercasing and
// de-duplicating. progress receives an integer percentage and result
// receives each hash's verdict; either may be nil. A failed lookup becomes
// an "error" verdict for that hash; only a missing key or a cancelled
// context fails the whole call.
//
// ponytail: no client-side throttling. Free keys allow about 4 lookups a
// minute; past that the API answers QuotaExceededError, surfaced per hash.
// Add a rate limiter here if large batches become common.
func LookupHashes(ctx context.Context, apiKey string, hashes []string,
	progress func(int), result func(hash, verdict, detail string)) (map[string]Verdict, error) {
	if apiKey == "" {
		return nil, errors.New("VirusTotal API key is required.")
	}
	var unique []string
	seen := map[string]bool{}
	for _, h := range hashes {
		if h = strings.ToLower(h); !seen[h] {
			seen[h] = true
			unique = append(unique, h)
		}
	}

	out := map[string]Verdict{}
	for i, digest := range unique {
		var v Verdict
		if len(digest) == 128 { // VirusTotal only indexes MD5/SHA1/SHA256
			v = Verdict{"n/a", "SHA512 not supported by VT"}
		} else {
			v = lookup(ctx, apiKey, digest)
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		out[digest] = v
		if result != nil {
			result(digest, v.Verdict, v.Detail)
		}
		if progress != nil {
			progress((i + 1) * 100 / len(unique))
		}
	}
	return out, nil
}

func lookup(ctx context.Context, apiKey, digest string) Verdict {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, BaseURL+"/files/"+digest, nil)
	if err != nil {
		return Verdict{"error", err.Error()}
	}
	req.Header.Set("x-apikey", apiKey)
	req.Header.Set("User-Agent", "HashHarvest")
	resp, err := client.Do(req)
	if err != nil {
		return Verdict{"error", err.Error()}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Verdict{"error", err.Error()}
	}

	if resp.StatusCode != http.StatusOK {
		code := apiErrorCode(resp, body)
		if code == "NotFoundError" {
			return Verdict{"not found", "not in VirusTotal"}
		}
		return Verdict{"error", code}
	}
	var payload struct {
		Data struct {
			Attributes struct {
				Stats map[string]int `json:"last_analysis_stats"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return Verdict{"error", err.Error()}
	}
	if payload.Data.Attributes.Stats == nil {
		return Verdict{"error", "response has no last_analysis_stats"}
	}
	verdict, detail := VerdictFromStats(payload.Data.Attributes.Stats)
	return Verdict{verdict, detail}
}

// apiErrorCode classifies a non-200 response the way vt-py does: the API's
// own error code from a JSON 4xx body, else ClientError or ServerError.
func apiErrorCode(resp *http.Response, body []byte) string {
	if resp.StatusCode < 400 || resp.StatusCode > 499 {
		return "ServerError"
	}
	if mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mediaType == "application/json" {
		var payload struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if json.Unmarshal(body, &payload) == nil && payload.Error.Code != "" {
			return payload.Error.Code
		}
	}
	return "ClientError"
}
