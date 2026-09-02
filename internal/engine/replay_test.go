package engine

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"jungle_happy_Scan/internal/callback"
	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/model"
)

func TestExpandReplayTemplateSupportsPaddingDictionaryAndBound(t *testing.T) {
	raw := "GET /api?pin={{int(0000-0002)}}&user={{x(dict)}} HTTP/1.1\r\nHost: bank.test\r\n\r\n"
	variants, truncated, err := ExpandReplayTemplate(raw, ReplayOptions{
		Dictionary: []string{"alice", "", "bob"}, MaxRequests: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !truncated || len(variants) != 5 {
		t.Fatalf("unexpected bound result: truncated=%v count=%d", truncated, len(variants))
	}
	expected := []string{
		"pin=0000&user=alice", "pin=0000&user=bob",
		"pin=0001&user=alice", "pin=0001&user=bob", "pin=0002&user=alice",
	}
	for index, fragment := range expected {
		if !strings.Contains(variants[index].RawHTTP, fragment) {
			t.Fatalf("variant %d missing %q: %s", index, fragment, variants[index].RawHTTP)
		}
	}
}

func TestExpandReplayTemplateRepeatsRawRequestWithoutPlaceholder(t *testing.T) {
	variants, truncated, err := ExpandReplayTemplate(
		"GET / HTTP/1.1\r\nHost: bank.test\r\n\r\n",
		ReplayOptions{Repeat: 3, MaxRequests: 10},
	)
	if err != nil || truncated || len(variants) != 3 || variants[2].Payload != "重复请求 #3" {
		t.Fatalf("unexpected repeated variants: %#v truncated=%v err=%v", variants, truncated, err)
	}
}

func TestRunReplayVariantsUsesConfiguredConcurrencyAndReturnsSummaries(t *testing.T) {
	var active atomic.Int64
	var peak atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			old := peak.Load()
			if current <= old || peak.CompareAndSwap(old, current) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		value := r.URL.Query().Get("value")
		w.Header().Set("X-Replay", value)
		_, _ = io.WriteString(w, strings.Repeat(value, 4))
	}))
	defer target.Close()
	targetURL, _ := url.Parse(target.URL)
	cfg := config.Default()
	cfg.Listen = "127.0.0.1:0"
	cfg.CallbackListen = "127.0.0.1:61166"
	cfg.CallbackLDAPListen = "127.0.0.1:61167"
	cfg.VerifyTLS = false
	cfg.AllowedHosts = []string{targetURL.Hostname()}
	cfg.RequestsPerSecond = 500
	cfg.GlobalRequestsPerSecond = 500
	cfg.GlobalMaxConcurrency = 20
	cfg.PerHostConcurrency = 20
	store, err := config.Open(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	callbacks := callback.NewWithLimit(8)
	defer callbacks.Close()
	manager := NewManager(store, callbacks)

	variants := make([]ReplayVariant, 20)
	for index := range variants {
		value := strconv.Itoa(index)
		variants[index] = ReplayVariant{
			Index: index + 1, Payload: "value=" + value,
			RawHTTP: fmt.Sprintf("GET /?value=%s HTTP/1.1\r\nHost: %s\r\n\r\n", value, targetURL.Host),
		}
	}
	var mu sync.Mutex
	var results []ReplayResult
	err = manager.RunReplayVariants(context.Background(), model.ScanInput{Scheme: "http"}, variants, 8, func(result ReplayResult) {
		mu.Lock()
		results = append(results, result)
		mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != len(variants) || peak.Load() < 2 {
		t.Fatalf("concurrent replay failed: results=%d peak=%d", len(results), peak.Load())
	}
	for _, result := range results {
		if result.Error != "" || result.StatusCode != http.StatusOK || result.ResponseBytes == 0 ||
			!strings.Contains(strings.ToLower(result.RawResponse), "x-replay:") {
			t.Fatalf("unexpected result: %#v", result)
		}
	}
}
