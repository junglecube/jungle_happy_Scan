package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/httpraw"
)

// Exercise actual HTTP, body mutation, re-signing, preflight, both synchronous
// API versions, and 3s/1.5s wall-clock delays. The target is an explicit HTTP
// fixture, not a claim of PostgreSQL/MySQL production integration coverage.
func TestSQL381SynchronousSignedBodyTiming(t *testing.T) {
	for _, kind := range []string{"form", "json"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			var sent, signed, rejected atomic.Int64
			mysql := regexp.MustCompile(`^' AND \(SELECT SLEEP\(([0-9.]+)\)\) AND '1'='1$`)
			pg := regexp.MustCompile(`^' AND \(SELECT 1 FROM pg_sleep\(([0-9.]+)\)\) AND '1'='2$`)
			if kind == "json" {
				pg = regexp.MustCompile(`^'\) AND 5014=\(SELECT 5014 FROM pg_sleep\(([0-9.]+)\)\) AND \('1'='1$`)
			}
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sent.Add(1)
				body, _ := io.ReadAll(r.Body)
				if r.Header.Get("X-Body-SHA") != fmt.Sprintf("%x", sha256.Sum256(body)) {
					rejected.Add(1)
					w.WriteHeader(403)
					return
				}
				var q1, q2 string
				if kind == "form" {
					values, _ := url.ParseQuery(string(body))
					q1, q2 = values.Get("query1"), values.Get("query2")
				} else {
					var input struct {
						Filter struct {
							Query1 string `json:"query1"`
							Query2 string `json:"query2"`
						} `json:"filter"`
					}
					_ = json.Unmarshal(body, &input)
					q1, q2 = input.Filter.Query1, input.Filter.Query2
				}
				status := 200
				for i, value := range []string{q1, q2} {
					re := mysql
					if i == 1 {
						re = pg
					}
					if match := re.FindStringSubmatch(value); len(match) == 2 {
						seconds, _ := strconv.ParseFloat(match[1], 64)
						time.Sleep(time.Duration(seconds * float64(time.Second)))
						// The second injected expression executes before a Java error.
						if i == 1 {
							status = 500
						}
					}
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_, _ = io.WriteString(w, `{"code":0,"rows":[]}`)
			}))
			defer target.Close()
			signer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var envelope struct {
					Request string `json:"request"`
				}
				if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
					w.WriteHeader(400)
					return
				}
				raw, err := base64.StdEncoding.DecodeString(envelope.Request)
				if err != nil {
					w.WriteHeader(400)
					return
				}
				req, err := httpraw.Parse(string(raw), "http")
				if err != nil {
					w.WriteHeader(400)
					return
				}
				signed.Add(1)
				req = req.WithHeader("X-Body-SHA", fmt.Sprintf("%x", sha256.Sum256(req.Body)))
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(struct {
					Request string `json:"request"`
				}{Request: base64.StdEncoding.EncodeToString(req.RawExact())})
			}))
			defer signer.Close()
			scanner := newTestServerWithConfig(t, target, "http", func(cfg *config.Config) { cfg.MaxRequests = 160; cfg.BaselineSamples = 2; cfg.TimeoutSeconds = 5 })
			defer scanner.Close()
			u, _ := url.Parse(target.URL)
			body, contentType := "query1=original&query2=original", "application/x-www-form-urlencoded"
			path := "/api/v1/jungle_happy_scan"
			if kind == "json" {
				body = `{"filter":{"query1":"original","query2":"original"}}`
				contentType = "application/json"
				path = "/api/v2/jungle_happy_scan_lite"
			}
			raw := fmt.Sprintf("POST /search HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nX-Body-SHA: old\r\nContent-Length: %d\r\n\r\n%s", u.Host, contentType, len(body), body)
			payload, _ := json.Marshal(map[string]any{"http": raw, "scheme": "http", "scan_type": []string{"sqli", "sqli_deep"}, "signature": map[string]any{"mode": "http", "endpoint": signer.URL}})
			client := &http.Client{Timeout: 40 * time.Second}
			response, err := client.Post(scanner.URL+path, "application/json", bytes.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			var result map[string]any
			if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
				t.Fatal(err)
			}
			findings, _ := result["findings"].([]any)
			if response.StatusCode != 200 || len(findings) != 2 {
				t.Fatalf("missed two signed parameters: status=%d result=%#v", response.StatusCode, result)
			}
			for _, item := range findings {
				finding := item.(map[string]any)
				if finding["plugin_id"] != "sqli_deep" || !strings.Contains(finding["title"].(string), "时间盲注") {
					t.Fatalf("wrong finding: %v", finding)
				}
			}
			if rejected.Load() != 0 || sent.Load() != signed.Load() {
				t.Fatalf("unsigned requests: sent=%d signed=%d rejected=%d", sent.Load(), signed.Load(), rejected.Load())
			}
			t.Logf("%s: two timing findings, %d signed target requests", kind, sent.Load())
		})
	}
}
