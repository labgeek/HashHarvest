package vt

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestVerdictFromStats(t *testing.T) {
	cases := []struct {
		stats           map[string]int
		verdict, detail string
	}{
		{map[string]int{"malicious": 5, "harmless": 60, "undetected": 7}, "malicious", "5/72"},
		{map[string]int{"malicious": 0, "suspicious": 2, "harmless": 70}, "suspicious", "2/72"},
		{map[string]int{"malicious": 0, "harmless": 70, "undetected": 2}, "clean", "0/72"},
		{map[string]int{"malicious": 1, "suspicious": 9}, "malicious", "1/10"},
		{map[string]int{}, "clean", "0/0"},
	}
	for _, tc := range cases {
		if v, d := VerdictFromStats(tc.stats); v != tc.verdict || d != tc.detail {
			t.Errorf("%v = %s %s, want %s %s", tc.stats, v, d, tc.verdict, tc.detail)
		}
	}
}

// serve points the package at a local server for the duration of the test.
func serve(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	server := httptest.NewServer(handler)
	saved := BaseURL
	BaseURL = server.URL
	t.Cleanup(func() { BaseURL = saved; server.Close() })
}

func TestLookupHashes(t *testing.T) {
	a, b, c, d := strings.Repeat("a", 32), strings.Repeat("b", 40), strings.Repeat("c", 64), strings.Repeat("d", 128)
	var paths []string
	serve(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.Header.Get("x-apikey") != "key" {
			t.Errorf("x-apikey = %q", r.Header.Get("x-apikey"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/files/" + a:
			fmt.Fprint(w, `{"data":{"attributes":{"last_analysis_stats":{"malicious":3,"harmless":7}}}}`)
		case "/files/" + b:
			w.WriteHeader(404)
			fmt.Fprint(w, `{"error":{"code":"NotFoundError","message":"nope"}}`)
		default:
			w.WriteHeader(429)
			fmt.Fprint(w, `{"error":{"code":"QuotaExceededError","message":"slow down"}}`)
		}
	})

	var progress []int
	var results []string
	out, err := LookupHashes(context.Background(), "key", []string{strings.ToUpper(a), b, a, c, d},
		func(p int) { progress = append(progress, p) },
		func(h, v, detail string) { results = append(results, h[:1]+":"+v+":"+detail) })
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Verdict{
		a: {"malicious", "3/10"},
		b: {"not found", "not in VirusTotal"},
		c: {"error", "QuotaExceededError"},
		d: {"n/a", "SHA512 not supported by VT"},
	}
	if !reflect.DeepEqual(out, want) {
		t.Errorf("out = %v", out)
	}
	// De-duplicated case-insensitively, order kept, SHA512 never sent.
	if want := []string{"/files/" + a, "/files/" + b, "/files/" + c}; !reflect.DeepEqual(paths, want) {
		t.Errorf("requests = %v", paths)
	}
	if want := []int{25, 50, 75, 100}; !reflect.DeepEqual(progress, want) {
		t.Errorf("progress = %v", progress)
	}
	if want := []string{"a:malicious:3/10", "b:not found:not in VirusTotal", "c:error:QuotaExceededError", "d:n/a:SHA512 not supported by VT"}; !reflect.DeepEqual(results, want) {
		t.Errorf("results = %v", results)
	}
}

func TestLookupErrorClassification(t *testing.T) {
	cases := []struct {
		status            int
		contentType, body string
		want              Verdict
	}{
		{400, "text/plain", "bad", Verdict{"error", "ClientError"}},
		{403, "application/json", `{"no_error_key": 1}`, Verdict{"error", "ClientError"}},
		{401, "application/json; charset=utf-8", `{"error":{"code":"WrongCredentialsError"}}`, Verdict{"error", "WrongCredentialsError"}},
		{500, "application/json", `{"error":{"code":"Ignored"}}`, Verdict{"error", "ServerError"}},
		{200, "application/json", `{"data":{"attributes":{}}}`, Verdict{"error", "response has no last_analysis_stats"}},
	}
	for _, tc := range cases {
		serve(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", tc.contentType)
			w.WriteHeader(tc.status)
			fmt.Fprint(w, tc.body)
		})
		got := lookup(context.Background(), "key", strings.Repeat("a", 32))
		if got != tc.want {
			t.Errorf("status %d %q: got %v, want %v", tc.status, tc.body, got, tc.want)
		}
	}
	serve(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "not json") })
	if got := lookup(context.Background(), "key", "x"); got.Verdict != "error" {
		t.Errorf("malformed body: %v", got)
	}
}

func TestLookupFailures(t *testing.T) {
	if _, err := LookupHashes(context.Background(), "", []string{"a"}, nil, nil); err == nil ||
		err.Error() != "VirusTotal API key is required." {
		t.Errorf("empty key: %v", err)
	}

	// A network failure is reported for that hash; the run continues.
	saved := BaseURL
	BaseURL = "http://127.0.0.1:1"
	out, err := LookupHashes(context.Background(), "key", []string{"abc"}, nil, nil)
	BaseURL = saved
	if err != nil || out["abc"].Verdict != "error" || out["abc"].Detail == "" {
		t.Errorf("unreachable server: %v, %v", out, err)
	}

	// Cancelling stops the run instead of reporting each remaining hash as an error.
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	serve(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		cancel()
		w.WriteHeader(500)
	})
	_, err = LookupHashes(ctx, "key", []string{"a", "b", "c"}, nil, nil)
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Errorf("cancel: err %v after %d requests", err, calls)
	}
}
