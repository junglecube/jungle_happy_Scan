package webscan

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"jungle_happy_Scan/internal/model"
)

type fakeScanner struct {
	mu       sync.Mutex
	inputs   []model.ScanInput
	canceled int
}

func TestStaticResourceDefaultsAndCustomExtensions(t *testing.T) {
	extensions, err := normalizeStaticExtensions([]string{"avif", ".WASM", "avif"})
	if err != nil {
		t.Fatal(err)
	}
	session := &Session{cfg: SessionConfig{StaticExtensions: extensions}}
	for _, value := range []string{"/app.js", "/logo.png", "/photo.avif", "/module.WASM"} {
		if !session.staticResource(value) {
			t.Fatalf("expected %s to be filtered", value)
		}
	}
	if session.staticResource("/account.jsp") {
		t.Fatal("dynamic JSP endpoint must not be filtered")
	}
	if _, err := normalizeStaticExtensions([]string{".tar.gz"}); err == nil {
		t.Fatal("compound extension must be rejected instead of being interpreted ambiguously")
	}
}

func TestInterceptionLongPollWakesOnPendingRequest(t *testing.T) {
	manager := New(&fakeScanner{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer manager.Close()
	created, err := manager.Create(SessionConfig{
		TargetURL: "http://bank.test", ProxyListen: "127.0.0.1:0",
		Plugins: []string{"sensitive_data"}, InterceptRequests: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, _ := manager.session(created.ID)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resolved := make(chan struct{})
	go func() {
		_, _ = session.awaitInterception(ctx, "request", "tx_test", "GET / HTTP/1.1\r\nHost: bank.test\r\n\r\n", "GET", "bank.test", "/", "", 0, true)
		close(resolved)
	}()
	items, revision, ok := manager.WaitInterceptions(context.Background(), created.ID, created.InterceptionRevision, time.Second)
	if !ok || revision <= created.InterceptionRevision || len(items) != 1 || items[0].Raw != "" || items[0].Status != "pending" {
		t.Fatalf("unexpected long poll result: ok=%v revision=%d items=%+v", ok, revision, items)
	}
	if err := manager.Decide(created.ID, items[0].ID, "forward", ""); err != nil {
		t.Fatal(err)
	}
	select {
	case <-resolved:
	case <-time.After(time.Second):
		t.Fatal("intercepted request was not released")
	}
}

func (f *fakeScanner) Start(input model.ScanInput, _ model.Response) (string, error) {
	f.mu.Lock()
	f.inputs = append(f.inputs, input)
	f.mu.Unlock()
	return "scan_test", nil
}

func (f *fakeScanner) Snapshot(string) (model.ScanView, []model.Finding, bool) {
	return model.ScanView{
		Status:   "completed",
		Progress: model.Progress{Phase: "completed", Percent: 100, RequestsSent: 1},
	}, []model.Finding{{ID: "finding_test", Severity: model.SeverityHigh}}, true
}

func (f *fakeScanner) Cancel(string) bool {
	f.mu.Lock()
	f.canceled++
	f.mu.Unlock()
	return true
}

func TestStopProxyPreservesSessionAndRunningScan(t *testing.T) {
	scanner := &fakeScanner{}
	manager := New(scanner, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer manager.Close()
	created, err := manager.Create(SessionConfig{
		TargetURL: "http://bank.test", ProxyListen: "127.0.0.1:0",
		Plugins: []string{"sensitive_data"}, AutoScan: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.InterceptTimeout != 60 || created.InterceptOnTimeout != "drop" {
		t.Fatalf("unexpected interception defaults: timeout=%d action=%s", created.InterceptTimeout, created.InterceptOnTimeout)
	}
	session, _ := manager.session(created.ID)
	asset := &Asset{ID: "asset_running", Fingerprint: "fingerprint_running", ScanID: "scan_running", ScanStatus: "scanning"}
	session.mu.Lock()
	session.assets[asset.ID] = asset
	session.assets[asset.Fingerprint] = asset
	session.order = append(session.order, asset.Fingerprint)
	session.mu.Unlock()

	if !manager.StopProxy(created.ID) {
		t.Fatal("proxy session was not found")
	}
	view, exists := manager.Get(created.ID)
	preserved, assetExists := manager.Asset(created.ID, asset.ID)
	scanner.mu.Lock()
	canceled := scanner.canceled
	scanner.mu.Unlock()
	if !exists || view.Status != "stopped" || !assetExists || preserved.ScanStatus != "scanning" || canceled != 0 {
		t.Fatalf("proxy stop changed scan/history state: exists=%v view=%#v asset=%#v canceled=%d", exists, view, preserved, canceled)
	}
}

func TestFingerprintUsesStructureInsteadOfValues(t *testing.T) {
	first, _ := http.NewRequest(http.MethodPost, "http://bank.test/api/user/1001?trace=a&id=1", strings.NewReader(`{"user":{"id":1,"name":"a"}}`))
	first.Header.Set("Content-Type", "application/json")
	second, _ := http.NewRequest(http.MethodPost, "http://bank.test/api/user/1002?id=9&trace=b", strings.NewReader(`{"user":{"name":"b","id":2}}`))
	second.Header.Set("Content-Type", "application/json")
	firstBody, _ := io.ReadAll(first.Body)
	secondBody, _ := io.ReadAll(second.Body)
	one, normalizedOne := fingerprintRequest(first, firstBody)
	two, normalizedTwo := fingerprintRequest(second, secondBody)
	if one != two || normalizedOne != "/api/user/{number}" || normalizedTwo != normalizedOne {
		t.Fatalf("equivalent interfaces were not deduplicated: %s %s %s %s", one, two, normalizedOne, normalizedTwo)
	}
}

func TestXMLFingerprintUsesNodeAndAttributeShape(t *testing.T) {
	first, _ := http.NewRequest(http.MethodPost, "http://bank.test/legacy/service", strings.NewReader(`<request type="a"><customer><id>1</id></customer></request>`))
	first.Header.Set("Content-Type", "application/xml")
	second, _ := http.NewRequest(http.MethodPost, "http://bank.test/legacy/service", strings.NewReader(`<request type="b"><customer><id>9</id></customer></request>`))
	second.Header.Set("Content-Type", "application/xml")
	firstBody, _ := io.ReadAll(first.Body)
	secondBody, _ := io.ReadAll(second.Body)
	one, _ := fingerprintRequest(first, firstBody)
	two, _ := fingerprintRequest(second, secondBody)
	if one != two {
		t.Fatalf("equivalent XML shapes were not deduplicated: %s %s", one, two)
	}
}

func TestGraphQLOperationsRemainDistinct(t *testing.T) {
	first, _ := http.NewRequest(http.MethodPost, "http://bank.test/graphql", strings.NewReader(`{"operationName":"QueryUser","query":"query QueryUser { user { id } }"}`))
	first.Header.Set("Content-Type", "application/json")
	second, _ := http.NewRequest(http.MethodPost, "http://bank.test/graphql", strings.NewReader(`{"operationName":"UpdateUser","query":"mutation UpdateUser { updateUser { id } }"}`))
	second.Header.Set("Content-Type", "application/json")
	firstBody, _ := io.ReadAll(first.Body)
	secondBody, _ := io.ReadAll(second.Body)
	one, _ := fingerprintRequest(first, firstBody)
	two, _ := fingerprintRequest(second, secondBody)
	if one == two {
		t.Fatal("different GraphQL operations were incorrectly merged")
	}
}

func TestHTTPProxyCaptureDeduplicateAndAutoScan(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true,"path":"`+r.URL.Path+`"}`)
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	scanner := &fakeScanner{}
	manager := New(scanner, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer manager.Close()
	created, err := manager.Create(SessionConfig{
		Name: "integration", TargetURL: upstream.URL, ProxyListen: "127.0.0.1:0",
		ScanMode: "normal", Plugins: []string{"sensitive_data"}, AutoScan: true, FilterStatic: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	proxyURL, _ := url.Parse("http://" + created.ProxyListen)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	for _, suffix := range []string{"/api/user/1001?id=1", "/api/user/1002?id=2"} {
		response, requestErr := client.Get(upstream.URL + suffix)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		assets, _ := manager.Assets(created.ID)
		if len(assets) == 1 && assets[0].SeenCount == 2 && assets[0].ScanStatus == "completed" {
			if assets[0].FindingsCount != 1 || assets[0].HighestSeverity != string(model.SeverityHigh) {
				t.Fatalf("scan result was not aggregated: %#v", assets[0])
			}
			session, _ := manager.Get(created.ID)
			if len(session.Findings) != 1 || session.Findings[0].AssetID != assets[0].ID ||
				session.Findings[0].InterfaceHost != target.Hostname() ||
				session.Findings[0].InterfacePath != "/api/user/{number}" {
				t.Fatalf("site finding is not linked to its interface asset: %#v", session.Findings)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	assets, _ := manager.Assets(created.ID)
	t.Fatalf("proxy capture did not converge: %#v target=%s", assets, target.Host)
}

func TestHTTPProxyForwardsCompressedWireBodyAndStoresDecodedUTF8(t *testing.T) {
	source := []byte(`<html><head><meta charset="GBK"></head><body>发送成功 /www/bank/app/index.html</body></html>`)
	encoded, _, err := transform.Bytes(simplifiedchinese.GBK.NewEncoder(), source)
	if err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err = writer.Write(encoded); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	wireBody := append([]byte(nil), compressed.Bytes()...)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			t.Errorf("proxy removed browser compression negotiation: %q", r.Header.Get("Accept-Encoding"))
		}
		w.Header().Set("Content-Type", "text/html; charset=gbk")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(wireBody)
	}))
	defer upstream.Close()
	manager := New(&fakeScanner{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer manager.Close()
	created, err := manager.Create(SessionConfig{
		TargetURL: upstream.URL, ProxyListen: "127.0.0.1:0",
		Plugins: []string{"sensitive_data"}, AutoScan: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	proxyURL, _ := url.Parse("http://" + created.ProxyListen)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableCompression: true}}
	request, _ := http.NewRequest(http.MethodGet, upstream.URL+"/legacy.jsp", nil)
	request.Header.Set("Accept-Encoding", "gzip, deflate")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	delivered, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if !bytes.Equal(delivered, wireBody) || response.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("browser wire response changed: encoding=%q body_equal=%v", response.Header.Get("Content-Encoding"), bytes.Equal(delivered, wireBody))
	}
	assets, _ := manager.Assets(created.ID)
	if len(assets) != 1 {
		t.Fatalf("expected one captured asset, got %d", len(assets))
	}
	detail, ok := manager.Asset(created.ID, assets[0].ID)
	if !ok {
		t.Fatal("captured asset detail missing")
	}
	if !strings.Contains(detail.RawResponse, "发送成功 /www/bank/app/index.html") ||
		strings.Contains(strings.ToLower(detail.RawResponse), "content-encoding: gzip") ||
		!bytes.Contains(detail.Baseline.Body, []byte("发送成功")) ||
		detail.Baseline.Charset != "gbk" {
		t.Fatalf("captured semantic response was not decoded: charset=%q raw=%q body=%q", detail.Baseline.Charset, detail.RawResponse, detail.Baseline.Body)
	}
}

func TestHTTPInterceptionModifyRequestAndResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Upstream", r.Header.Get("X-Edited"))
		_, _ = fmt.Fprintf(w, "%s|%s", r.URL.Path, body)
	}))
	defer upstream.Close()
	manager := New(&fakeScanner{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer manager.Close()
	created, err := manager.Create(SessionConfig{
		TargetURL: upstream.URL, ProxyListen: "127.0.0.1:0", Plugins: []string{"sensitive_data"},
		InterceptRequests: true, InterceptResponses: true, InterceptTimeout: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	proxyURL, _ := url.Parse("http://" + created.ProxyListen)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	result := make(chan string, 1)
	go func() {
		request, _ := http.NewRequest(http.MethodPost, upstream.URL+"/original", strings.NewReader("before"))
		response, requestErr := client.Do(request)
		if requestErr != nil {
			result <- "error:" + requestErr.Error()
			return
		}
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		result <- fmt.Sprintf("%d|%s|%s", response.StatusCode, response.Header.Get("X-Edited-Response"), body)
	}()
	requestItem := waitPendingInterception(t, manager, created.ID, "request")
	modifiedRequest := strings.Replace(requestItem.Raw, "/original", "/changed", 1)
	modifiedRequest = strings.Replace(modifiedRequest, "\r\n\r\nbefore", "\r\nX-Edited: yes\r\n\r\nafter", 1)
	if err := manager.Decide(created.ID, requestItem.ID, "forward", modifiedRequest); err != nil {
		t.Fatal(err)
	}
	responseItem := waitPendingInterception(t, manager, created.ID, "response")
	modifiedResponse := strings.Replace(responseItem.Raw, "HTTP/1.1 200 OK", "HTTP/1.1 201 Created", 1)
	modifiedResponse = strings.Replace(modifiedResponse, "\r\n\r\n/changed|after", "\r\nX-Edited-Response: yes\r\n\r\nbrowser-body", 1)
	if err := manager.Decide(created.ID, responseItem.ID, "forward", modifiedResponse); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-result:
		if got != "201|yes|browser-body" {
			t.Fatalf("modified transaction was not delivered: %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("intercepted transaction did not finish")
	}
}

func TestHTTPInterceptionDropsRequestBeforeUpstream(t *testing.T) {
	var called bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		_, _ = io.WriteString(w, "unexpected")
	}))
	defer upstream.Close()
	manager := New(&fakeScanner{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer manager.Close()
	created, err := manager.Create(SessionConfig{
		TargetURL: upstream.URL, ProxyListen: "127.0.0.1:0", Plugins: []string{"sensitive_data"},
		InterceptRequests: true, InterceptTimeout: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	proxyURL, _ := url.Parse("http://" + created.ProxyListen)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	result := make(chan int, 1)
	go func() {
		response, requestErr := client.Get(upstream.URL + "/drop")
		if requestErr != nil {
			result <- 0
			return
		}
		_ = response.Body.Close()
		result <- response.StatusCode
	}()
	item := waitPendingInterception(t, manager, created.ID, "request")
	if err := manager.Decide(created.ID, item.ID, "drop", ""); err != nil {
		t.Fatal(err)
	}
	if status := <-result; status != http.StatusForbidden || called {
		t.Fatalf("request drop failed: status=%d upstream_called=%v", status, called)
	}
}

func TestHTTPInterceptionDropsResponseAndDisableReleasesPending(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "upstream")
	}))
	defer upstream.Close()
	manager := New(&fakeScanner{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer manager.Close()
	created, err := manager.Create(SessionConfig{
		TargetURL: upstream.URL, ProxyListen: "127.0.0.1:0", Plugins: []string{"sensitive_data"},
		InterceptResponses: true, InterceptTimeout: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	proxyURL, _ := url.Parse("http://" + created.ProxyListen)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	result := make(chan string, 1)
	go func() {
		response, requestErr := client.Get(upstream.URL + "/drop-response")
		if requestErr != nil {
			result <- requestErr.Error()
			return
		}
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		result <- fmt.Sprintf("%d|%s", response.StatusCode, body)
	}()
	item := waitPendingInterception(t, manager, created.ID, "response")
	if err := manager.Decide(created.ID, item.ID, "drop", ""); err != nil {
		t.Fatal(err)
	}
	if got := <-result; !strings.HasPrefix(got, "403|") {
		t.Fatalf("response was not dropped: %q", got)
	}

	go func() {
		response, requestErr := client.Get(upstream.URL + "/auto-release")
		if requestErr != nil {
			result <- requestErr.Error()
			return
		}
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		result <- string(body)
	}()
	_ = waitPendingInterception(t, manager, created.ID, "response")
	if _, err := manager.UpdateInterception(created.ID, InterceptionSettings{}); err != nil {
		t.Fatal(err)
	}
	if got := <-result; got != "upstream" {
		t.Fatalf("disabling interception did not release response: %q", got)
	}
}

func waitPendingInterception(t *testing.T, manager *Manager, sessionID, direction string) InterceptionView {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		items, _ := manager.Interceptions(sessionID)
		for _, item := range items {
			if item.Direction == direction && item.Status == "pending" {
				detail, ok := manager.Interception(sessionID, item.ID)
				if !ok {
					t.Fatalf("interception %s disappeared", item.ID)
				}
				return detail
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("pending %s interception not found", direction)
	return InterceptionView{}
}

func TestOutOfScopeRequestPassesThroughLoopbackWithoutCapture(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "outside-ok")
	}))
	defer upstream.Close()
	scanner := &fakeScanner{}
	manager := New(scanner, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer manager.Close()
	created, err := manager.Create(SessionConfig{TargetURL: "http://bank.test", ProxyListen: "127.0.0.1:0", Plugins: []string{"sensitive_data"}})
	if err != nil {
		t.Fatal(err)
	}
	proxyURL, _ := url.Parse("http://" + created.ProxyListen)
	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	}}
	response, err := client.Get(upstream.URL + "/outside")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	assets, _ := manager.Assets(created.ID)
	if response.StatusCode != http.StatusOK || string(body) != "outside-ok" || len(assets) != 0 {
		t.Fatalf("out-of-scope pass-through was incorrect: status=%d body=%q assets=%#v", response.StatusCode, body, assets)
	}
}

func TestOutOfScopeRequestIsRejectedOnRemoteListener(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "must-not-forward")
	}))
	defer upstream.Close()
	manager := New(&fakeScanner{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer manager.Close()
	created, err := manager.Create(SessionConfig{
		TargetURL: "http://bank.test", ProxyListen: "0.0.0.0:0",
		Plugins: []string{"sensitive_data"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(created.ProxyListen)
	proxyURL, _ := url.Parse("http://127.0.0.1:" + port)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	response, err := client.Get(upstream.URL + "/outside")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("remote listener forwarded an out-of-scope target: %d", response.StatusCode)
	}
}

func TestGlobalPassiveScopeForwardsAndCapturesMultipleHosts(t *testing.T) {
	alpha := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "alpha")
	}))
	defer alpha.Close()
	beta := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "beta")
	}))
	defer beta.Close()
	alphaURL, _ := url.Parse(alpha.URL)
	betaURL, _ := url.Parse(beta.URL)

	manager := New(&fakeScanner{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer manager.Close()
	manager.transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		switch host {
		case "alpha.test":
			address = alphaURL.Host
		case "beta.test":
			address = betaURL.Host
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	created, err := manager.Create(SessionConfig{
		TargetURL: "*", ProxyListen: "127.0.0.1:0", ScanMode: "passive",
		Plugins: []string{"sensitive_data"}, AutoScan: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !created.GlobalScope || created.TargetURL != "*" || len(created.ScopeHosts) != 1 || created.ScopeHosts[0] != "*" {
		t.Fatalf("global scope was not normalized: %#v", created)
	}
	proxyURL, _ := url.Parse("http://" + created.ProxyListen)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	for _, target := range []string{"http://alpha.test/api/a", "http://beta.test/api/b"} {
		response, requestErr := client.Get(target)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("global proxy rejected %s: %d", target, response.StatusCode)
		}
	}
	assets, _ := manager.Assets(created.ID)
	if len(assets) != 2 {
		t.Fatalf("global proxy did not capture both hosts: %#v", assets)
	}
}

func TestGlobalScopeRejectsActiveMode(t *testing.T) {
	manager := New(&fakeScanner{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer manager.Close()
	for _, target := range []string{"", "*"} {
		if _, err := manager.Create(SessionConfig{
			TargetURL: target, ProxyListen: "127.0.0.1:0", ScanMode: "normal",
			Plugins: []string{"sqli"}, AutoScan: true,
		}); err == nil || !strings.Contains(err.Error(), "只允许使用 passive") {
			t.Fatalf("global active mode was not rejected for target %q: %v", target, err)
		}
	}
	if _, err := manager.Create(SessionConfig{
		TargetURL: "*", ProxyListen: "0.0.0.0:0", ScanMode: "passive",
		Plugins: []string{"sensitive_data"}, AutoScan: true,
	}); err == nil || !strings.Contains(err.Error(), "环回地址") {
		t.Fatalf("network-exposed global proxy was not rejected: %v", err)
	}
}

func TestPersistentManagerRecoversCapturedAssetsWithoutRestartingProxy(t *testing.T) {
	stateDir := t.TempDir()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"code":0,"message":"saved"}`)
	}))
	defer upstream.Close()
	first := NewPersistent(&fakeScanner{}, slog.New(slog.NewTextHandler(io.Discard, nil)), stateDir)
	created, err := first.Create(SessionConfig{
		TargetURL: upstream.URL, ProxyListen: "127.0.0.1:0",
		Plugins: []string{"sensitive_data"}, AutoScan: false, BrowserOwner: "browser-old",
	})
	if err != nil {
		t.Fatal(err)
	}
	proxyURL, _ := url.Parse("http://" + created.ProxyListen)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	response, err := client.Get(upstream.URL + "/api/recovery?id=1")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	first.Close()

	second := NewPersistent(&fakeScanner{}, slog.New(slog.NewTextHandler(io.Discard, nil)), stateDir)
	defer second.Close()
	sessions := second.List()
	if len(sessions) != 1 || sessions[0].Status != "stopped" || sessions[0].BrowserOwner != "" {
		t.Fatalf("recovered session metadata is incorrect: %#v", sessions)
	}
	assets, ok := second.Assets(sessions[0].ID)
	if !ok || len(assets) != 1 {
		t.Fatalf("captured assets were not recovered: ok=%v assets=%#v", ok, assets)
	}
	detail, ok := second.Asset(sessions[0].ID, assets[0].ID)
	if !ok || !strings.Contains(detail.RawRequest, "/api/recovery?id=1") ||
		!strings.Contains(detail.RawResponse, `"message":"saved"`) {
		t.Fatalf("representative HTTP evidence was not recovered: %#v", detail)
	}
	if sessions[0].ProxyListen == "" {
		t.Fatal("recovered stopped task lost its configured proxy address")
	}
	if err := second.Scan(sessions[0].ID, assets[0].ID); err != nil {
		t.Fatalf("cold recovered asset could not be loaded for an explicit rescan: %v", err)
	}
}

func TestAssetsPageAndFindingSummariesKeepLargeListsLightweight(t *testing.T) {
	manager := New(&fakeScanner{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer manager.Close()
	created, err := manager.Create(SessionConfig{
		TargetURL: "http://bank.test", ProxyListen: "127.0.0.1:0",
		Plugins: []string{"sensitive_data"}, AutoScan: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, _ := manager.session(created.ID)
	session.mu.Lock()
	for index := 0; index < 125; index++ {
		id := fmt.Sprintf("asset_%03d", index)
		status := "completed"
		if index%10 == 0 {
			status = "failed"
		}
		asset := &Asset{
			ID: id, Fingerprint: id, Method: "GET", Host: "bank.test",
			NormalizedPath: fmt.Sprintf("/api/customer/%03d", index), ScanStatus: status,
			FirstSeen: time.Unix(int64(index), 0), LastSeen: time.Unix(int64(index), 0), ResponseBytes: int64(index + 100),
			RawRequest: strings.Repeat("request", 1000), RawResponse: strings.Repeat("response", 1000),
			Findings: []model.Finding{{
				ID: id + "_finding", Severity: model.SeverityLow,
				Evidence: []model.Evidence{{Request: "large request", Response: "large response"}},
			}},
		}
		session.assets[id] = asset
		session.order = append(session.order, id)
	}
	session.mu.Unlock()

	page, total, ok := manager.AssetsPage(created.ID, "", "", 2, 50)
	if !ok || total != 125 || len(page) != 50 {
		t.Fatalf("unexpected second page: ok=%v total=%d length=%d", ok, total, len(page))
	}
	if page[0].NormalizedPath != "/api/customer/074" || page[0].ResponseBytes != 174 {
		t.Fatalf("assets are not ordered by newest last_seen or response size was lost: %#v", page[0])
	}
	for _, asset := range page {
		if asset.RawRequest != "" || asset.RawResponse != "" || len(asset.Findings) != 0 {
			t.Fatalf("asset page leaked heavy detail: %#v", asset)
		}
	}
	failed, failedTotal, ok := manager.AssetsPage(created.ID, "customer", "failed", 1, 100)
	if !ok || failedTotal != 13 || len(failed) != 13 {
		t.Fatalf("server-side filters are incorrect: ok=%v total=%d length=%d", ok, failedTotal, len(failed))
	}
	findings, ok := manager.FindingSummaries(created.ID)
	if !ok || len(findings) != 125 {
		t.Fatalf("finding summaries missing: ok=%v length=%d", ok, len(findings))
	}
	for _, finding := range findings {
		if len(finding.Evidence) != 0 {
			t.Fatal("finding summary retained heavyweight evidence")
		}
	}
}

func TestHistoricalAssetsSpanSessionsAndClearWithoutStoppingProxy(t *testing.T) {
	manager := New(&fakeScanner{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer manager.Close()
	first, err := manager.Create(SessionConfig{
		TargetURL: "http://first.test", ProxyListen: "127.0.0.1:0",
		Plugins: []string{"sensitive_data"}, AutoScan: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.Create(SessionConfig{
		TargetURL: "http://second.test", ProxyListen: "127.0.0.1:0",
		Plugins: []string{"sensitive_data"}, AutoScan: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	for index, sessionID := range []string{first.ID, second.ID} {
		session, _ := manager.session(sessionID)
		id := fmt.Sprintf("history_%d", index)
		session.mu.Lock()
		session.assets[id] = &Asset{
			ID: id, Fingerprint: id, Method: "GET", Host: fmt.Sprintf("host%d.test", index),
			NormalizedPath: "/api/history", ScanStatus: "completed", SeenCount: 1,
			FirstSeen: time.Unix(int64(index+1), 0), LastSeen: time.Unix(int64(index+1), 0),
			Findings: []model.Finding{{ID: id + "_finding", Title: "历史发现"}},
		}
		session.order = append(session.order, id)
		session.observed = 1
		session.mu.Unlock()
	}
	assets, total := manager.HistoricalAssetsPage("", "", 1, 50)
	if total != 2 || len(assets) != 2 || assets[0].WebScanID != second.ID {
		t.Fatalf("historical assets were not merged and sorted: total=%d assets=%#v", total, assets)
	}
	findings := manager.HistoricalFindingSummaries()
	if len(findings) != 2 || findings[0].WebScanID == "" {
		t.Fatalf("historical findings lost their session identity: %#v", findings)
	}
	if removed := manager.ClearHistoricalAssets(); removed != 2 {
		t.Fatalf("unexpected removed asset count: %d", removed)
	}
	assets, total = manager.HistoricalAssetsPage("", "", 1, 50)
	if total != 0 || len(assets) != 0 {
		t.Fatalf("historical assets survived clear: total=%d assets=%#v", total, assets)
	}
	summary, ok := manager.Summary(first.ID)
	if !ok || summary.Status != "listening" {
		t.Fatalf("clearing history stopped or deleted proxy task: %#v ok=%v", summary, ok)
	}
}

func TestGlobalChangeNotificationWakesImmediately(t *testing.T) {
	manager := New(&fakeScanner{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer manager.Close()
	initial := manager.WaitChanges(context.Background(), 0, time.Second)
	result := make(chan uint64, 1)
	go func() {
		result <- manager.WaitChanges(context.Background(), initial, 2*time.Second)
	}()
	time.Sleep(20 * time.Millisecond)
	manager.notifyChange()
	select {
	case revision := <-result:
		if revision <= initial {
			t.Fatalf("change revision did not advance: initial=%d current=%d", initial, revision)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("global change listener was not woken by notification")
	}
}

func TestRecoveryReadersFallBackToWindowsBackup(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "session.json")
	if err := os.WriteFile(jsonPath+".bak", []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := readRecoveryFile(jsonPath)
	if err != nil || string(data) != `{"version":1}` {
		t.Fatalf("plain backup was not recovered: data=%q err=%v", data, err)
	}
	gzipPath := filepath.Join(dir, "asset.json.gz")
	expected := map[string]string{"id": "asset_backup"}
	if err := atomicWriteGzip(gzipPath+".bak", expected); err != nil {
		t.Fatal(err)
	}
	var restored map[string]string
	if err := readGzipJSON(gzipPath, &restored); err != nil || restored["id"] != expected["id"] {
		t.Fatalf("gzip backup was not recovered: value=%#v err=%v", restored, err)
	}
}

func TestHTTPSTunnelDoesNotCreateDecryptedAsset(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "secure")
	}))
	defer upstream.Close()
	scanner := &fakeScanner{}
	manager := New(scanner, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer manager.Close()
	created, err := manager.Create(SessionConfig{
		TargetURL: upstream.URL, ProxyListen: "127.0.0.1:0",
		Plugins: []string{"sensitive_data"}, AutoScan: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	proxyURL, _ := url.Parse("http://" + created.ProxyListen)
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // local test server only
	}}
	response, err := client.Get(upstream.URL + "/private")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if string(body) != "secure" {
		t.Fatalf("CONNECT did not forward TLS bytes: %q", body)
	}
	assets, _ := manager.Assets(created.ID)
	session, _ := manager.Get(created.ID)
	if len(assets) != 0 || session.Counters.HTTPSTunnels != 1 {
		t.Fatalf("HTTPS tunnel was incorrectly treated as decrypted traffic: assets=%#v counters=%#v", assets, session.Counters)
	}
}

func TestHTTPSMITMCapturesMTLSPlaintextAndKeepsHTTPSForScan(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if len(request.TLS.PeerCertificates) == 0 {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, "mTLS secure response")
	}))
	upstream.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS12}
	upstream.StartTLS()
	defer upstream.Close()

	clientPEM := makeClientCertificatePEM(t)
	clientPath := filepath.Join(t.TempDir(), "client.pem")
	if err := os.WriteFile(clientPath, clientPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	scanner := &fakeScanner{}
	manager := New(scanner, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer manager.Close()
	created, err := manager.Create(SessionConfig{
		TargetURL: upstream.URL, ProxyListen: "127.0.0.1:0", Plugins: []string{"sensitive_data"},
		InterceptTLS: true, ClientTLSFile: clientPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, ok := manager.session(created.ID)
	if !ok || session.transport == nil || session.transport.TLSClientConfig == nil {
		t.Fatal("mTLS proxy session was not initialized")
	}
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	session.transport.TLSClientConfig.RootCAs = roots

	caPEM, err := manager.RootCertificate()
	if err != nil {
		t.Fatal(err)
	}
	browserRoots := x509.NewCertPool()
	if !browserRoots.AppendCertsFromPEM(caPEM) {
		t.Fatal("proxy CA could not be parsed")
	}
	proxyURL, _ := url.Parse("http://" + created.ProxyListen)
	browser := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: browserRoots, MinVersion: tls.VersionTLS12},
	}}
	response, err := browser.Get(upstream.URL + "/private")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "mTLS secure response" {
		t.Fatalf("unexpected mTLS proxy response: status=%d body=%q", response.StatusCode, body)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		assets, _ := manager.Assets(created.ID)
		if len(assets) == 1 {
			asset, found := manager.Asset(created.ID, assets[0].ID)
			if !found || asset.Scheme != "https" || !strings.Contains(asset.RawRequest, "GET /private HTTP/1.1") ||
				!strings.Contains(asset.RawResponse, "mTLS secure response") {
				t.Fatalf("HTTPS plaintext capture is incomplete: %#v", asset)
			}
			if err := manager.Scan(created.ID, assets[0].ID); err != nil {
				t.Fatal(err)
			}
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	for time.Now().Before(deadline) {
		scanner.mu.Lock()
		inputs := append([]model.ScanInput(nil), scanner.inputs...)
		scanner.mu.Unlock()
		if len(inputs) == 1 {
			if inputs[0].Scheme != "https" {
				t.Fatalf("captured HTTPS asset must be sent back to scanner as HTTPS: %#v", inputs)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("captured HTTPS asset was not sent to scanner")
}

func TestProxyCAFilesArePrivateAndClientPasswordIsNotRetained(t *testing.T) {
	stateDir := t.TempDir()
	manager := NewPersistent(&fakeScanner{}, slog.New(slog.NewTextHandler(io.Discard, nil)), stateDir)
	defer manager.Close()
	created, err := manager.Create(SessionConfig{
		TargetURL: "https://bank.test", ProxyListen: "127.0.0.1:0", InterceptTLS: true,
		ClientTLSPassword: "must-not-persist",
	})
	if err != nil {
		t.Fatal(err)
	}
	session, _ := manager.session(created.ID)
	if session.cfg.ClientTLSPassword != "" {
		t.Fatal("client certificate password was retained in session config")
	}
	for _, name := range []string{"happy-scan-proxy-ca.pem", "happy-scan-proxy-ca-key.pem"} {
		info, statErr := os.Stat(filepath.Join(stateDir, "proxy_ca", name))
		if statErr != nil {
			t.Fatal(statErr)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("proxy CA file permissions must be 0600, got %o", info.Mode().Perm())
		}
	}
}

func makeClientCertificatePEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(3501), Subject: pkix.Name{CommonName: "happy-scan-mtls-test"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})...)
}

func TestConcurrentProxyRequestsDeduplicateSafely(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	manager := New(&fakeScanner{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer manager.Close()
	created, err := manager.Create(SessionConfig{
		TargetURL: upstream.URL, ProxyListen: "127.0.0.1:0",
		Plugins: []string{"sensitive_data"}, AutoScan: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	proxyURL, _ := url.Parse("http://" + created.ProxyListen)
	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(proxyURL), MaxIdleConns: 100, MaxIdleConnsPerHost: 100,
	}}
	const requests = 80
	var group sync.WaitGroup
	errorsFound := make(chan error, requests)
	for index := 0; index < requests; index++ {
		group.Add(1)
		go func(value int) {
			defer group.Done()
			response, requestErr := client.Get(upstream.URL + "/api/order/" + fmt.Sprint(1000+value) + "?id=" + fmt.Sprint(value))
			if requestErr != nil {
				errorsFound <- requestErr
				return
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
		}(index)
	}
	group.Wait()
	close(errorsFound)
	for requestErr := range errorsFound {
		t.Fatal(requestErr)
	}
	assets, _ := manager.Assets(created.ID)
	if len(assets) != 1 || assets[0].SeenCount != requests {
		t.Fatalf("concurrent equivalent requests were not deduplicated: %#v", assets)
	}
}
