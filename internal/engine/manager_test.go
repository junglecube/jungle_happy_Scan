package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"jungle_happy_Scan/internal/callback"
	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/model"
)

func TestRequestProgressUsesResolvedRequestSlots(t *testing.T) {
	task := &Task{
		progress: model.Progress{
			Phase:           "scanning",
			Percent:         10,
			PlannedRequests: 20,
			Plugins: map[string]model.PluginProgress{
				"sqli": {Name: "SQL 注入", Total: 16, Status: "queued"},
				"cors": {Name: "CORS", Total: 4, Status: "queued"},
			},
		},
		subs: make(map[int]chan Event),
	}
	task.requestProgress("sqli", "SQL 注入", 1)
	if got := task.View().Progress; got.ResolvedRequests != 1 || got.Percent != 14 {
		t.Fatalf("one resolved request should drive request progress: %#v", got)
	}
	task.finishPluginProgress("sqli", "SQL 注入", "completed", 1, true)
	got := task.View().Progress
	if got.ResolvedRequests != 16 || got.RequestsSkipped != 15 || got.Percent != 81 {
		t.Fatalf("early convergence should resolve unused request slots: %#v", got)
	}
	task.finishPluginProgress("cors", "CORS", "partial", 2, false)
	got = task.View().Progress
	if got.ResolvedRequests != 20 || got.RequestsSkipped != 17 || got.BudgetSkipped != 2 || got.Percent != 99 {
		t.Fatalf("partial plugin should resolve, but separately classify, uncovered request slots: %#v", got)
	}
}

func TestSQLPluginsUseExclusiveOracleLane(t *testing.T) {
	for _, id := range []string{"sqli", "sqli_extended", "sqli_timing", "sqli_order_by", "sqli_limit", "mybatis_dynamic_sql"} {
		if !sqlOracleLane(id) {
			t.Fatalf("%s was not assigned to the SQL oracle lane", id)
		}
	}
	for _, id := range []string{"reflected_xss", "error_disclosure", "command_injection"} {
		if sqlOracleLane(id) {
			t.Fatalf("%s must retain normal staged scheduling", id)
		}
	}
}

func TestSQLTimingExactReplacementDetectsQuotedQuery(t *testing.T) {
	var valuesMu sync.Mutex
	var values []string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("query")
		valuesMu.Lock()
		values = append(values, value)
		valuesMu.Unlock()
		if value == "' AND (SELECT SLEEP(3)) AND '1'='1" {
			time.Sleep(3 * time.Second)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer target.Close()

	store, err := config.Open(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := store.Get()
	cfg.TimeoutSeconds = 5
	cfg.MaxRequests = 40
	cfg.BaselineSamples = 2
	cfg.RequestsPerSecond = 500
	parsed, _ := url.Parse(target.URL)
	cfg.AllowedHosts = []string{parsed.Hostname()}
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	callbacks := callback.New()
	defer callbacks.Close()
	manager := NewManager(store, callbacks)
	raw := fmt.Sprintf("GET /search?query=original HTTP/1.1\r\nHost: %s\r\n\r\n", parsed.Host)
	task, err := manager.Create(model.ScanInput{HTTP: raw, ScanType: []string{"sqli_timing"}, Scheme: "http"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if err := task.Wait(ctx); err != nil {
		t.Fatalf("timing scan did not complete: %v", err)
	}
	if task.View().Status != "completed" {
		t.Fatalf("timing scan ended unexpectedly: %#v", task.View())
	}
	found := false
	for _, finding := range task.Findings() {
		if finding.Title == "SQL 时间盲注" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("exact quoted-query timing injection was missed: findings=%#v", task.Findings())
	}
	valuesMu.Lock()
	defer valuesMu.Unlock()
	seenExactPayload := false
	for _, value := range values {
		if value == "' AND (SELECT SLEEP(3)) AND '1'='1" {
			seenExactPayload = true
		}
		if strings.HasPrefix(value, "original'") {
			t.Fatalf("timing payload incorrectly retained original value: %q", value)
		}
	}
	if !seenExactPayload {
		t.Fatalf("scanner never sent the verified timing payload: %#v", values)
	}
}

func TestNonIdempotentPreflightIsOnlyBaselineAndPlanUsesOneSample(t *testing.T) {
	var requests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-CSRF-Token", "fresh-token")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer target.Close()
	store, err := config.Open(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := store.Get()
	cfg.BaselineSamples = 3
	cfg.MaxRequests = 20
	cfg.RequestsPerSecond = 500
	cfg.ResponseExtractors = []config.ResponseExtractor{{
		Name: "csrf", Source: "header:X-CSRF-Token", Pattern: `(.+)`, Destination: "header:X-CSRF-Token",
	}}
	parsed, _ := url.Parse(target.URL)
	cfg.AllowedHosts = []string{parsed.Hostname()}
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	callbacks := callback.New()
	defer callbacks.Close()
	manager := NewManager(store, callbacks)
	raw := fmt.Sprintf("POST /state HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nX-CSRF-Token: stale\r\n\r\n{}", parsed.Host)
	input := model.ScanInput{HTTP: raw, ScanType: []string{"sensitive_data"}, Scheme: "http"}
	plan, err := manager.Plan(input)
	if err != nil {
		t.Fatal(err)
	}
	if plan.RequestBudget != 19 {
		t.Fatalf("POST plan reserved more than one baseline: budget=%d", plan.RequestBudget)
	}
	preflight, err := manager.CheckConnectivity(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	task, err := manager.CreateWithPreflight(input, preflight)
	if err != nil {
		t.Fatal(err)
	}
	waitTask(t, task)
	if got := requests.Load(); got != 1 {
		t.Fatalf("preflight POST was repeated during scan: requests=%d", got)
	}
	if task.preflight != nil {
		t.Fatal("task retained preflight request/response after baseline setup")
	}
	if task.request.Header("X-CSRF-Token") != "fresh-token" {
		t.Fatalf("preflight extractor was not applied before scanning: %q", task.request.Header("X-CSRF-Token"))
	}
}

func TestBaselineSamplesForSafeAndStateChangingMethods(t *testing.T) {
	for _, test := range []struct {
		method string
		want   int
	}{{http.MethodGet, 3}, {http.MethodHead, 3}, {http.MethodOptions, 3}, {http.MethodPost, 1}, {http.MethodPatch, 1}, {http.MethodDelete, 1}} {
		if got := baselineSamplesFor(test.method, 3); got != test.want {
			t.Fatalf("baselineSamplesFor(%s)=%d want %d", test.method, got, test.want)
		}
	}
}

func TestProgressEventsAreThrottledAndFindingsDeduplicateIncrementally(t *testing.T) {
	events := make(chan Event, 4)
	task := &Task{
		subs:        map[int]chan Event{0: events},
		findingKeys: make(map[string]struct{}),
	}
	view := model.ScanView{Status: "running"}
	task.publishProgress(view, false)
	task.publishProgress(view, false)
	if got := len(events); got != 1 {
		t.Fatalf("progress events were not throttled: %d", got)
	}
	time.Sleep(110 * time.Millisecond)
	task.publishProgress(view, false)
	if got := len(events); got != 2 {
		t.Fatalf("progress event was not emitted after throttle window: %d", got)
	}
	finding := model.Finding{PluginID: "test", Affected: "query:id", Title: "duplicate"}
	task.addFindings([]model.Finding{finding, finding})
	task.addFindings([]model.Finding{finding})
	if got := len(task.Findings()); got != 1 {
		t.Fatalf("incremental finding deduplication retained %d items", got)
	}
	if len(task.correlations) != 0 {
		t.Fatal("correlation was recomputed during incremental insertion")
	}
}

func TestGlobalActiveScanLimit(t *testing.T) {
	var active atomic.Int32
	var peak atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			old := peak.Load()
			if current <= old || peak.CompareAndSwap(old, current) {
				break
			}
		}
		time.Sleep(80 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":"000000"}`))
	}))
	defer target.Close()

	store, err := config.Open(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := store.Get()
	cfg.DefaultScheme = "http"
	cfg.BaselineSamples = 1
	cfg.MaxActiveScans = 1
	cfg.RequestsPerSecond = 500
	cfg.VerifyTLS = false
	parsed, _ := url.Parse(target.URL)
	cfg.AllowedHosts = []string{parsed.Hostname()}
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(store, callback.New())
	raw := fmt.Sprintf("GET /data HTTP/1.1\r\nHost: %s\r\n\r\n", parsed.Host)
	first, err := manager.Create(model.ScanInput{HTTP: raw, ScanType: []string{"sensitive_data"}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.Create(model.ScanInput{HTTP: raw, ScanType: []string{"sensitive_data"}})
	if err != nil {
		t.Fatal(err)
	}
	waitTask(t, first)
	waitTask(t, second)
	if peak.Load() != 1 {
		t.Fatalf("expected global scan limit 1, observed %d concurrent target requests", peak.Load())
	}
}

func TestQueueCapacityCheckIsAtomicAndDeleteCancelsExpiry(t *testing.T) {
	store, err := config.Open(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := store.Get()
	cfg.MaxActiveScans = 1
	cfg.MaxQueuedScans = 1
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(store, callback.New())
	// Occupy the only process slot so every accepted task remains visibly queued.
	manager.slotMu.Lock()
	manager.active = 1
	manager.slotMu.Unlock()

	const attempts = 24
	accepted := make(chan *Task, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			task, createErr := manager.Create(model.ScanInput{
				HTTP: "GET / HTTP/1.1\r\nHost: queue.test\r\n\r\n", ScanType: []string{"sensitive_data"},
			})
			if createErr == nil {
				accepted <- task
			}
		}()
	}
	wg.Wait()
	close(accepted)
	var tasks []*Task
	for task := range accepted {
		tasks = append(tasks, task)
	}
	if len(tasks) != 1 {
		t.Fatalf("queue limit accepted %d concurrent tasks, want 1", len(tasks))
	}
	task := tasks[0]
	if !manager.Delete(task.ID()) {
		t.Fatal("accepted task could not be deleted")
	}
	select {
	case <-task.expireCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("deleting task did not cancel its expiry lifecycle")
	}
}

func waitTask(t *testing.T, task *Task) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		status := task.View().Status
		if status == "completed" {
			return
		}
		if status == "failed" || status == "cancelled" {
			t.Fatalf("task ended as %s: %s", status, task.View().Error)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("task did not finish")
}
