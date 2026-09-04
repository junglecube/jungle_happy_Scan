package api

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"jungle_happy_Scan/internal/callback"
	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/engine"
	"jungle_happy_Scan/internal/model"
)

func TestClientTLSUploadPreservesFilename(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer target.Close()
	scanner := newTestServer(t, target)
	defer scanner.Close()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "bank-client.pem")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(part, "dummy-pem-for-upload-test")
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodPost, scanner.URL+"/api/v1/client-tls-files", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result map[string]any
	_ = json.NewDecoder(response.Body).Decode(&result)
	path, _ := result["client_tls_file"].(string)
	if response.StatusCode != http.StatusCreated || filepath.Base(path) != "bank-client.pem" {
		t.Fatalf("upload did not preserve filename: status=%d result=%#v", response.StatusCode, result)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("uploaded certificate permissions invalid: info=%#v err=%v", info, err)
	}
}

func TestProxyCADownloadReturnsUsableCertificate(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer target.Close()
	scanner := newTestServer(t, target)
	defer scanner.Close()
	response, err := http.Get(scanner.URL + "/api/v3/proxy-ca")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	block, _ := pem.Decode(body)
	certificate, parseErr := x509.ParseCertificate(func() []byte {
		if block == nil {
			return nil
		}
		return block.Bytes
	}())
	if response.StatusCode != http.StatusOK || block == nil || parseErr != nil || !certificate.IsCA {
		t.Fatalf("proxy CA download is invalid: status=%d block=%#v cert=%#v err=%v", response.StatusCode, block, certificate, parseErr)
	}
}

func TestScanAPIReportsPairedSQLInjection(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(id, "'") && !strings.HasSuffix(id, "''") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"error":"java.sql.SQLSyntaxErrorException: unclosed quotation mark"}`)
			return
		}
		_, _ = io.WriteString(w, `{"code":"000000","data":{"name":"tester"}}`)
	}))
	defer target.Close()
	scanner := newTestServer(t, target)
	defer scanner.Close()
	targetURL, _ := url.Parse(target.URL)
	raw := fmt.Sprintf("GET /api/user?id=1 HTTP/1.1\r\nHost: %s\r\nCookie: JSESSIONID=test\r\n\r\n", targetURL.Host)
	body, _ := json.Marshal(map[string]any{"http": raw, "scan_type": []string{"sqli"}})
	response, err := http.Post(scanner.URL+"/api/v1/scan", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		data, _ := io.ReadAll(response.Body)
		t.Fatalf("unexpected create status %d: %s", response.StatusCode, data)
	}
	var created map[string]any
	_ = json.NewDecoder(response.Body).Decode(&created)
	id := created["scan_id"].(string)
	result := waitResult(t, scanner.URL, id)
	findings := result["findings"].([]any)
	if len(findings) != 1 {
		t.Fatalf("expected one SQLi finding, got %#v", findings)
	}
	finding := findings[0].(map[string]any)
	if finding["plugin_id"] != "sqli" || finding["confidence"] != "已确认" {
		t.Fatalf("unexpected finding: %#v", finding)
	}
}

func TestV2FindingUsesStableCodesAndChineseLabels(t *testing.T) {
	items := convertV2Findings([]model.Finding{{
		ID: "f1", PluginID: "sqli", Title: "SQL", Severity: model.SeverityHigh,
		Confidence: model.ConfidenceCertain, Category: "确认漏洞", Score: 93, Correlation: "corr_1",
		Evidence: []model.Evidence{{Request: "GET /", Response: "HTTP/1.1 500", Strength: "L4"}},
	}}, true)
	if len(items) != 1 || items[0].Severity != "high" || items[0].SeverityLabel != "高危" ||
		items[0].Confidence != "certain" || items[0].ConfidenceLabel != "已确认" ||
		items[0].Evidence[0].Request != "" || items[0].Evidence[0].Response != "" || items[0].Evidence[0].Strength != "L4" ||
		items[0].Category != "confirmed" || items[0].CategoryLabel != "确认漏洞" || items[0].Score != 93 || items[0].CorrelationID != "corr_1" {
		t.Fatalf("unexpected V2 finding: %+v", items)
	}
}

func TestV2PluginMetadataIncludesRulePackDigest(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer target.Close()
	scanner := newTestServer(t, target)
	defer scanner.Close()
	response, err := http.Get(scanner.URL + "/api/v2/plugins")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var body map[string]any
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	digest, _ := body["rule_pack_digest"].(string)
	if body["api_version"] != "2.0" || !strings.HasPrefix(digest, "sha256:") || len(digest) != len("sha256:")+24 {
		t.Fatalf("V2 plugin metadata missing stable rule digest: %#v", body)
	}
}

func TestReplayAPIRunsParameterizedRequests(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.URL.Query().Get("pin")
		w.Header().Set("X-Pin", value)
		_, _ = io.WriteString(w, "pin="+value)
	}))
	defer target.Close()
	scanner := newTestServer(t, target)
	defer scanner.Close()
	targetURL, _ := url.Parse(target.URL)
	raw := fmt.Sprintf("GET /login?pin={{int(0001-0003)}} HTTP/1.1\r\nHost: %s\r\n\r\n", targetURL.Host)
	body, _ := json.Marshal(map[string]any{
		"http": raw, "scheme": "http", "concurrency": 3, "max_requests": 10,
	})
	response, err := http.Post(scanner.URL+"/api/v1/replays", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var created struct {
		ReplayID string `json:"replay_id"`
		Total    int    `json:"total"`
	}
	_ = json.NewDecoder(response.Body).Decode(&created)
	if response.StatusCode != http.StatusAccepted || created.ReplayID == "" || created.Total != 3 {
		t.Fatalf("unexpected replay create response: status=%d payload=%#v", response.StatusCode, created)
	}
	var snapshot struct {
		Status    string `json:"status"`
		Completed int    `json:"completed"`
		Results   []struct {
			ID         string `json:"id"`
			Payload    string `json:"payload"`
			StatusCode int    `json:"status_code"`
		} `json:"results"`
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		response, err = http.Get(scanner.URL + "/api/v1/replays/" + created.ReplayID + "?page_size=10")
		if err != nil {
			t.Fatal(err)
		}
		snapshot = struct {
			Status    string `json:"status"`
			Completed int    `json:"completed"`
			Results   []struct {
				ID         string `json:"id"`
				Payload    string `json:"payload"`
				StatusCode int    `json:"status_code"`
			} `json:"results"`
		}{}
		_ = json.NewDecoder(response.Body).Decode(&snapshot)
		_ = response.Body.Close()
		if snapshot.Status == "completed" {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if snapshot.Status != "completed" || snapshot.Completed != 3 || len(snapshot.Results) != 3 || snapshot.Results[0].StatusCode != http.StatusOK {
		t.Fatalf("unexpected replay snapshot: %#v", snapshot)
	}
	response, err = http.Get(scanner.URL + "/api/v1/replays/" + created.ReplayID + "/results/" + snapshot.Results[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var detail struct {
		Result struct {
			RawResponse string `json:"raw_response"`
		} `json:"result"`
	}
	_ = json.NewDecoder(response.Body).Decode(&detail)
	if response.StatusCode != http.StatusOK || !strings.Contains(strings.ToLower(detail.Result.RawResponse), "x-pin:") {
		t.Fatalf("unexpected replay detail: status=%d detail=%#v", response.StatusCode, detail)
	}
}

func TestV3WebScanLifecycleCapturesHTTPAsset(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"code":0,"path":"`+r.URL.Path+`"}`)
	}))
	defer target.Close()
	scanner := newTestServer(t, target)
	defer scanner.Close()
	createBody, _ := json.Marshal(map[string]any{
		"name": "V3 integration", "target_url": target.URL, "proxy_listen": "127.0.0.1:0",
		"scan_mode": "normal", "auto_scan": false, "filter_static": true,
	})
	response, err := http.Post(scanner.URL+"/api/v3/web-scans", "application/json", bytes.NewReader(createBody))
	if err != nil {
		t.Fatal(err)
	}
	var created struct {
		WebScan struct {
			ID          string `json:"id"`
			ProxyListen string `json:"proxy_listen"`
		} `json:"web_scan"`
	}
	_ = json.NewDecoder(response.Body).Decode(&created)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusCreated || created.WebScan.ID == "" || created.WebScan.ProxyListen == "" {
		t.Fatalf("unexpected V3 create response: status=%d payload=%#v", response.StatusCode, created)
	}
	proxyURL, _ := url.Parse("http://" + created.WebScan.ProxyListen)
	browser := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	response, err = browser.Get(target.URL + "/api/customer/1001?id=1")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	response, err = http.Get(scanner.URL + "/api/v3/web-scans/" + created.WebScan.ID + "/assets")
	if err != nil {
		t.Fatal(err)
	}
	var listed struct {
		Assets []struct {
			ID             string `json:"id"`
			NormalizedPath string `json:"normalized_path"`
			SeenCount      int    `json:"seen_count"`
		} `json:"assets"`
	}
	_ = json.NewDecoder(response.Body).Decode(&listed)
	_ = response.Body.Close()
	if len(listed.Assets) != 1 || listed.Assets[0].NormalizedPath != "/api/customer/{number}" || listed.Assets[0].SeenCount != 1 {
		t.Fatalf("captured asset is incorrect: %#v", listed.Assets)
	}
	request, _ := http.NewRequest(http.MethodDelete, scanner.URL+"/api/v3/web-scans/"+created.WebScan.ID+"/proxy", nil)
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("V3 proxy stop failed: %d", response.StatusCode)
	}
	request, _ = http.NewRequest(http.MethodPost, scanner.URL+"/api/v3/web-scans/"+created.WebScan.ID+"/assets/"+listed.Assets[0].ID+"/scan", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("manual V3 asset scan was not accepted: %d", response.StatusCode)
	}
	request, _ = http.NewRequest(http.MethodDelete, scanner.URL+"/api/v3/web-scans/"+created.WebScan.ID, nil)
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("V3 session delete failed: %d", response.StatusCode)
	}
}

func TestV3GlobalScopeRequiresPassivePlugins(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer target.Close()
	scanner := newTestServer(t, target)
	defer scanner.Close()

	for _, body := range []string{
		`{"target_url":"*","proxy_listen":"127.0.0.1:0","scan_mode":"normal"}`,
		`{"target_url":"","proxy_listen":"127.0.0.1:0","scan_mode":"passive","plugins":["sqli"]}`,
	} {
		response, err := http.Post(scanner.URL+"/api/v3/web-scans", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("unsafe global scan was accepted: status=%d body=%s", response.StatusCode, body)
		}
	}

	response, err := http.Post(scanner.URL+"/api/v3/web-scans", "application/json", strings.NewReader(
		`{"target_url":"*","proxy_listen":"127.0.0.1:0","scan_mode":"passive","auto_scan":true}`,
	))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var created struct {
		WebScan struct {
			ID          string   `json:"id"`
			GlobalScope bool     `json:"global_scope"`
			TargetURL   string   `json:"target_url"`
			ScopeHosts  []string `json:"scope_hosts"`
			Plugins     []string `json:"plugins"`
		} `json:"web_scan"`
	}
	_ = json.NewDecoder(response.Body).Decode(&created)
	if response.StatusCode != http.StatusCreated || !created.WebScan.GlobalScope ||
		created.WebScan.TargetURL != "*" || len(created.WebScan.Plugins) != 3 {
		t.Fatalf("global Passive task was not normalized: status=%d payload=%#v", response.StatusCode, created)
	}
}

func TestV2SyncReusesConnectivityResponseAsBaseline(t *testing.T) {
	var requests int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, `<html><body>contact: security@example.test</body></html>`)
	}))
	defer target.Close()
	scanner := newTestServer(t, target)
	defer scanner.Close()
	targetURL, _ := url.Parse(target.URL)
	payload := map[string]any{
		"http":      "GET /profile.jsp HTTP/1.1\r\nHost: " + targetURL.Host + "\r\n\r\n",
		"scan_type": []string{"sensitive_data"}, "scheme": "http",
	}
	body, _ := json.Marshal(payload)
	response, err := http.Post(scanner.URL+"/api/v2/jungle_happy_scan", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result struct {
		APIVersion string `json:"api_version"`
		Findings   []struct {
			Severity      string `json:"severity"`
			SeverityLabel string `json:"severity_label"`
		} `json:"findings"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || result.APIVersion != "2.0" || len(result.Findings) == 0 || result.Findings[0].Severity == "" || result.Findings[0].SeverityLabel == "" {
		t.Fatalf("unexpected V2 response: status=%d result=%+v", response.StatusCode, result)
	}
	// The test server config uses baseline_samples=1. Reuse therefore means the
	// connectivity request is the only unmodified request; V1.41 sent it twice.
	if requests != 1 {
		t.Fatalf("connectivity response was not reused: original request count=%d want=1", requests)
	}
}

func TestSynchronousAuthPreflightStopsDeniedResponses(t *testing.T) {
	var requests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"message":"登录失败"}`)
	}))
	defer target.Close()
	scanner := newTestServerWithConfig(t, target, "http", func(cfg *config.Config) {
		cfg.DeniedPatterns = []string{`登录失败`}
	})
	defer scanner.Close()
	targetURL, _ := url.Parse(target.URL)
	raw := fmt.Sprintf("GET /private HTTP/1.1\r\nHost: %s\r\nCookie: JSESSIONID=valid\r\n\r\n", targetURL.Host)
	body, _ := json.Marshal(map[string]any{"http": raw, "scan_type": []string{"sensitive_data"}, "scheme": "http"})

	for _, path := range []string{
		"/api/v1/jungle_happy_scan",
		"/jungle_happy_scan",
		"/api/v1/jungle_happy_scan_lite",
		"/jungle_happy_scan_lite",
		"/api/v2/jungle_happy_scan",
		"/api/v2/jungle_happy_scan_lite",
	} {
		response, err := http.Post(scanner.URL+path, "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		var result map[string]any
		if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
			_ = response.Body.Close()
			t.Fatal(err)
		}
		_ = response.Body.Close()
		scan := result["scan"].(map[string]any)
		connectivity := result["connectivity"].(map[string]any)
		findings := result["findings"].([]any)
		if response.StatusCode != http.StatusOK || scan["status"] != "failed" || scan["scan_id"] != "" || len(findings) != 0 {
			t.Fatalf("denied synchronous scan was not stopped: path=%s result=%#v", path, result)
		}
		if connectivity["ok"] != false || connectivity["network_ok"] != true || connectivity["auth_valid"] != false ||
			connectivity["reason"] != "auth_denied" || connectivity["matched_rule"] != "denied_pattern[0]" {
			t.Fatalf("denied preflight diagnostics are incomplete: path=%s connectivity=%#v", path, connectivity)
		}
		if _, exists := result["api_version"]; strings.HasPrefix(path, "/api/v2/") != exists {
			t.Fatalf("unexpected V2 metadata: path=%s result=%#v", path, result)
		}
	}
	if got := requests.Load(); got != 6 {
		t.Fatalf("denied synchronous requests should stop after one preflight each: got=%d want=6", got)
	}
}

func TestManualConnectivityDoesNotApplyAuthGate(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"message":"登录失败"}`)
	}))
	defer target.Close()
	scanner := newTestServerWithConfig(t, target, "http", func(cfg *config.Config) {
		cfg.DeniedPatterns = []string{`登录失败`}
	})
	defer scanner.Close()
	targetURL, _ := url.Parse(target.URL)
	raw := fmt.Sprintf("GET /private HTTP/1.1\r\nHost: %s\r\n\r\n", targetURL.Host)
	body, _ := json.Marshal(map[string]any{"http": raw, "scheme": "http"})
	response, err := http.Post(scanner.URL+"/api/v1/connectivity", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result map[string]any
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || result["ok"] != true {
		t.Fatalf("manual connectivity unexpectedly applied auth gate: %#v", result)
	}
	if _, exists := result["auth_valid"]; exists {
		t.Fatalf("manual connectivity response should retain network-only contract: %#v", result)
	}
}

func TestSynchronousAuthPreflightStopsStatusDeniedResponses(t *testing.T) {
	var requests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		status := http.StatusUnauthorized
		if r.URL.Query().Get("status") == "403" {
			status = http.StatusForbidden
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, "denied")
	}))
	defer target.Close()
	scanner := newTestServer(t, target)
	defer scanner.Close()
	targetURL, _ := url.Parse(target.URL)

	for _, test := range []struct {
		status int
		path   string
	}{
		{status: http.StatusUnauthorized, path: "/private?status=401"},
		{status: http.StatusForbidden, path: "/private?status=403"},
	} {
		raw := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", test.path, targetURL.Host)
		body, _ := json.Marshal(map[string]any{"http": raw, "scan_type": []string{"sensitive_data"}, "scheme": "http"})
		response, err := http.Post(scanner.URL+"/api/v1/jungle_happy_scan", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		var result map[string]any
		if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
			_ = response.Body.Close()
			t.Fatal(err)
		}
		_ = response.Body.Close()
		connectivity := result["connectivity"].(map[string]any)
		if response.StatusCode != http.StatusOK || connectivity["ok"] != false || connectivity["network_ok"] != true ||
			connectivity["auth_valid"] != false || connectivity["matched_rule"] != fmt.Sprintf("status_code[%d]", test.status) {
			t.Fatalf("status denial was not reported: status=%d result=%#v", test.status, result)
		}
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("status-denied synchronous scans should send only preflight requests: got=%d want=2", got)
	}
}

func TestAsyncScanDoesNotApplySynchronousAuthGate(t *testing.T) {
	var requests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = io.WriteString(w, `{"message":"登录失败"}`)
	}))
	defer target.Close()
	scanner := newTestServerWithConfig(t, target, "http", func(cfg *config.Config) {
		cfg.DeniedPatterns = []string{`登录失败`}
	})
	defer scanner.Close()
	targetURL, _ := url.Parse(target.URL)
	raw := fmt.Sprintf("GET /private HTTP/1.1\r\nHost: %s\r\n\r\n", targetURL.Host)
	body, _ := json.Marshal(map[string]any{"http": raw, "scan_type": []string{"sensitive_data"}, "scheme": "http"})
	response, err := http.Post(scanner.URL+"/api/v1/scan", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var created map[string]any
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		_ = response.Body.Close()
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("async scan was incorrectly blocked by synchronous auth gate: status=%d result=%#v", response.StatusCode, created)
	}
	result := waitResult(t, scanner.URL, created["scan_id"].(string))
	if result["scan"].(map[string]any)["status"] != "completed" {
		t.Fatalf("async scan did not complete: %#v", result)
	}
	if requests.Load() == 0 {
		t.Fatal("async scan did not send its baseline request")
	}
}

func TestPlanAPIReportsApplicabilityAndBudget(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer target.Close()
	scanner := newTestServer(t, target)
	defer scanner.Close()
	targetURL, _ := url.Parse(target.URL)
	raw := fmt.Sprintf("GET /api/users/42?id=1 HTTP/1.1\r\nHost: %s\r\n\r\n", targetURL.Host)
	body, _ := json.Marshal(map[string]any{"http": raw, "scheme": "http", "scan_type": []string{"sqli", "xxe", "sensitive_data"}})
	response, err := http.Post(scanner.URL+"/api/v1/plan", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result struct {
		DiscoveredPoints     int                             `json:"discovered_points"`
		EstimatedRequests    int                             `json:"estimated_requests"`
		CompleteWithinBudget bool                            `json:"complete_within_budget"`
		Plugins              map[string]model.PluginCoverage `json:"plugins"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || result.DiscoveredPoints < 2 || result.EstimatedRequests == 0 ||
		result.Plugins["xxe"].Status != "skipped" || !result.CompleteWithinBudget {
		t.Fatalf("unexpected scan plan: status=%d result=%#v", response.StatusCode, result)
	}
}

func TestConfigAPIAndEmbeddedPage(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer target.Close()
	scanner := newTestServer(t, target)
	defer scanner.Close()
	response, err := http.Get(scanner.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != 200 || !bytes.Contains(page, []byte("jungle_happy_Scan")) {
		t.Fatalf("embedded page unavailable: %d %s", response.StatusCode, page)
	}
	if csp := response.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "style-src 'self' 'unsafe-inline'") {
		t.Fatalf("CodeMirror requires inline editor styles, got CSP: %s", csp)
	}
	if !bytes.Contains(page, []byte("cfg-rule-payloads")) || !bytes.Contains(page, []byte(`id="cfg-rule-url-keywords"`)) ||
		!bytes.Contains(page, []byte("jungle.jpg")) || !bytes.Contains(page, []byte("version-view")) ||
		!bytes.Contains(page, []byte("V3.6.3")) || !bytes.Contains(page, []byte(`id="proxy-view"`)) ||
		!bytes.Contains(page, []byte(`id="assets-view"`)) ||
		!bytes.Contains(page, []byte(`data-view="proxy"`)) || !bytes.Contains(page, []byte(`data-view="assets"`)) ||
		bytes.Contains(page, []byte(`data-view="webscan"`)) || !bytes.Contains(page, []byte(`src="/codemirror.js?v=3.6.3"`)) || !bytes.Contains(page, []byte(`src="/webscan.js?v=3.6.3"`)) ||
		!bytes.Contains(page, []byte(`id="webscan-interception-panel"`)) ||
		!bytes.Contains(page, []byte(`id="webscan-interception-forward"`)) ||
		!bytes.Contains(page, []byte(`id="webscan-interception-drop"`)) ||
		bytes.Contains(page, []byte(`id="webscan-interception-list"`)) ||
		bytes.Contains(page, []byte(`id="webscan-interception-forward-modified"`)) ||
		bytes.Contains(page, []byte(`id="webscan-intercept-timeout"`)) ||
		bytes.Contains(page, []byte(`id="webscan-session-select"`)) ||
		bytes.Contains(page, []byte(`id="webscan-name"`)) ||
		!bytes.Contains(page, []byte(`class="webscan-detail-pair"`)) ||
		!bytes.Contains(page, []byte(`id="webscan-detail-request"`)) ||
		!bytes.Contains(page, []byte(`id="webscan-detail-response"`)) ||
		!bytes.Contains(page, []byte(`id="webscan-config-tab"`)) ||
		!bytes.Contains(page, []byte(`id="webscan-assets-tab"`)) ||
		!bytes.Contains(page, []byte(`id="webscan-detail-space"`)) ||
		!bytes.Contains(page, []byte(`id="webscan-detail-placeholder"`)) ||
		!bytes.Contains(page, []byte(`<th>漏洞数量</th>`)) ||
		bytes.Contains(page, []byte(`<th>最高风险</th>`)) ||
		bytes.Contains(page, []byte(`id="webscan-detail-meta"`)) ||
		!bytes.Contains(page, []byte(`id="webscan-copy-request"`)) ||
		!bytes.Contains(page, []byte(`id="webscan-assets-pagination"`)) ||
		!bytes.Contains(page, []byte(`id="webscan-clear-history"`)) ||
		!bytes.Contains(page, []byte(`id="webscan-static-extensions"`)) ||
		!bytes.Contains(page, []byte("mode-option")) ||
		!bytes.Contains(page, []byte("scan-mode-help")) || !bytes.Contains(page, []byte("Normal")) ||
		!bytes.Contains(page, []byte(`id="plugin-progress"`)) || !bytes.Contains(page, []byte("guide-view")) ||
		!bytes.Contains(page, []byte("cfg-callback-listen")) || !bytes.Contains(page, []byte("v2-architecture")) ||
		!bytes.Contains(page, []byte("cfg-global-concurrency")) || !bytes.Contains(page, []byte("cfg-callback-ldap-listen")) || !bytes.Contains(page, []byte("cfg-callback-max-connections")) ||
		!bytes.Contains(page, []byte("client-tls-file-input")) || !bytes.Contains(page, []byte("cfg-sqli-errors")) ||
		!bytes.Contains(page, []byte("cfg-excluded-params")) ||
		bytes.Contains(page, []byte(`<h1>HTTP接口快速扫描引擎</h1>`)) ||
		bytes.Contains(page, []byte(`id="proxy-title"`)) || bytes.Contains(page, []byte(`id="assets-title"`)) ||
		!bytes.Contains(page, []byte(`id="http-request" class="cm-http-editor"`)) ||
		!bytes.Contains(page, []byte(`<h2>请求报文</h2>`)) || !bytes.Contains(page, []byte(`<h2>返回报文</h2>`)) ||
		!bytes.Contains(page, []byte(`id="response-placeholder"`)) || !bytes.Contains(page, []byte(`<th>返回长度</th>`)) ||
		bytes.Contains(page, []byte("Go · V2.4")) || bytes.Contains(page, []byte("cfg-scheme")) ||
		bytes.Contains(page, []byte(`id="coverage-report"`)) ||
		bytes.Contains(page, []byte(`id="select-all"`)) ||
		bytes.Contains(page, []byte(`<select id="scan-mode"`)) || bytes.Contains(page, []byte("cfg-mode")) {
		t.Fatalf("V3.6.3 UI assets are missing or obsolete controls remain: %s", page)
	}
	if bytes.Index(page, []byte(`data-mode="custom"`)) < bytes.Index(page, []byte(`data-mode="deep"`)) || !bytes.Contains(page, []byte("52 个")) {
		t.Fatalf("Custom must be last and V2 plugin count must be current")
	}
	response, err = http.Get(scanner.URL + "/app.js")
	if err != nil {
		t.Fatal(err)
	}
	app, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if bytes.Contains(app, []byte("backendScanMode")) || bytes.Contains(app, []byte("mode:backendScanMode")) ||
		!bytes.Contains(app, []byte("const payload=withClientTLS({http,scheme,scan_type})")) ||
		!bytes.Contains(app, []byte("pluginGroups")) || !bytes.Contains(app, []byte("resolved_requests")) ||
		!bytes.Contains(app, []byte("Promise.all([ensurePlugins(),ensureConfig()])")) ||
		!bytes.Contains(app, []byte("HappyScanEditor.create")) ||
		!bytes.Contains(app, []byte("renderPluginProgress(progress.plugins||{},scan.coverage||{})")) ||
		bytes.Contains(app, []byte("renderCoverage(")) {
		t.Fatalf("Web scan must submit plugin IDs without a hidden mode: %s", app)
	}
	response, err = http.Get(scanner.URL + "/styles.css")
	if err != nil {
		t.Fatal(err)
	}
	stylesheet, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK ||
		!strings.HasPrefix(response.Header.Get("Content-Type"), "text/css") ||
		!bytes.Contains(stylesheet, []byte(".topbar")) ||
		bytes.Contains(stylesheet, []byte("<!doctype html>")) {
		t.Fatalf("embedded stylesheet unavailable: status=%d type=%q", response.StatusCode, response.Header.Get("Content-Type"))
	}
	response, err = http.Get(scanner.URL + "/webscan.js")
	if err != nil {
		t.Fatal(err)
	}
	webScanApp, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || !bytes.Contains(webScanApp, []byte("/api/v3/web-scans")) ||
		!bytes.Contains(webScanApp, []byte("webscan-assets-body")) ||
		!bytes.Contains(webScanApp, []byte("/history/assets")) ||
		!bytes.Contains(webScanApp, []byte("/history/findings")) ||
		!bytes.Contains(webScanApp, []byte("since: String(state.interceptionRevision)")) ||
		!bytes.Contains(webScanApp, []byte("wait: '1'")) ||
		!bytes.Contains(webScanApp, []byte("assetPageSize: 10")) ||
		bytes.Contains(webScanApp, []byte("activateWebScanTab")) ||
		bytes.Contains(webScanApp, []byte("webscan-inline-detail-row")) ||
		bytes.Contains(webScanApp, []byte("scrollIntoView")) ||
		bytes.Contains(webScanApp, []byte("intercepting ? 200")) ||
		!bytes.Contains(webScanApp, []byte("navigator.clipboard")) || !bytes.Contains(webScanApp, []byte("webscan-intercept-tls")) ||
		bytes.Contains(webScanApp, []byte("sendBeacon('/api/v3/web-scans/browser-close'")) {
		t.Fatalf("V3 WEB scan frontend controller is unavailable: status=%d", response.StatusCode)
	}
	response, err = http.Get(scanner.URL + "/plugins.md")
	if err != nil {
		t.Fatal(err)
	}
	manual, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if !bytes.Contains(manual, []byte("5.50 异常信息泄露扩展诱导")) || bytes.Contains(manual, []byte("只有 Deep 执行 `mode: deep`")) {
		t.Fatalf("embedded plugin manual was not synchronized")
	}
	response, err = http.Get(scanner.URL + "/jungle.jpg")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 || !strings.HasPrefix(response.Header.Get("Content-Type"), "image/jpeg") || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("embedded logo unavailable or cached: status=%d type=%q cache=%q", response.StatusCode, response.Header.Get("Content-Type"), response.Header.Get("Cache-Control"))
	}
	_ = response.Body.Close()
	response, err = http.Get(scanner.URL + "/callback/not-a-real-token")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("main management listener must not serve OAST callbacks: status=%d", response.StatusCode)
	}
	_ = response.Body.Close()
	response, err = http.Get(scanner.URL + "/api/v1/config")
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	_ = json.NewDecoder(response.Body).Decode(&payload)
	_ = response.Body.Close()
	cfg := payload["config"].(map[string]any)
	cfg["max_concurrency"] = float64(11)
	encoded, _ := json.Marshal(cfg)
	request, _ := http.NewRequest(http.MethodPut, scanner.URL+"/api/v1/config", bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusForbidden {
		data, _ := io.ReadAll(response.Body)
		t.Fatalf("config save without password should fail: %d %s", response.StatusCode, data)
	}
	_ = response.Body.Close()

	request, _ = http.NewRequest(http.MethodPut, scanner.URL+"/api/v1/config", bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Jungle-Config-Password", "jungle")
	response, err = http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 {
		data, _ := io.ReadAll(response.Body)
		t.Fatalf("config save failed: %d %s", response.StatusCode, data)
	}
	_ = response.Body.Close()
}

func TestConnectivityAutoUsesHTTPFirst(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"code":"000000","message":"reachable"}`)
	}))
	defer target.Close()
	scanner := newTestServerScheme(t, target, "https")
	defer scanner.Close()
	targetURL, _ := url.Parse(target.URL)
	raw := fmt.Sprintf("GET /health HTTP/1.1\r\nHost: %s\r\n\r\n", targetURL.Host)
	body, _ := json.Marshal(map[string]any{"http": raw, "scheme": "auto"})
	response, err := http.Post(scanner.URL+"/api/v1/connectivity", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var connectivity map[string]any
	_ = json.NewDecoder(response.Body).Decode(&connectivity)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || connectivity["ok"] != true || connectivity["scheme"] != "http" || connectivity["auto_fallback"] != false {
		t.Fatalf("unexpected connectivity result: status=%d payload=%#v", response.StatusCode, connectivity)
	}
	if !strings.Contains(connectivity["raw_response"].(string), "reachable") {
		t.Fatalf("raw response missing target body: %#v", connectivity)
	}

	scanBody, _ := json.Marshal(map[string]any{"http": raw, "scheme": "auto", "scan_type": []string{"sensitive_data"}})
	response, err = http.Post(scanner.URL+"/api/v1/scan", "application/json", bytes.NewReader(scanBody))
	if err != nil {
		t.Fatal(err)
	}
	var created map[string]any
	_ = json.NewDecoder(response.Body).Decode(&created)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("scan create failed: status=%d payload=%#v", response.StatusCode, created)
	}
	result := waitResult(t, scanner.URL, created["scan_id"].(string))
	scan := result["scan"].(map[string]any)
	if warnings := scan["warnings"]; warnings != nil && len(warnings.([]any)) != 0 {
		t.Fatalf("working HTTP must not produce protocol fallback warning: %#v", scan)
	}
}

func TestConnectivityAutoFallsBackToHTTPS(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "https-auto-ok")
	}))
	defer target.Close()
	scanner := newTestServerScheme(t, target, "http")
	defer scanner.Close()
	targetURL, _ := url.Parse(target.URL)
	raw := fmt.Sprintf("GET /secure HTTP/1.1\r\nHost: %s\r\n\r\n", targetURL.Host)
	body, _ := json.Marshal(map[string]any{"http": raw, "scheme": "auto"})
	response, err := http.Post(scanner.URL+"/api/v1/connectivity", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result map[string]any
	_ = json.NewDecoder(response.Body).Decode(&result)
	if result["ok"] != true || result["scheme"] != "https" || result["auto_fallback"] != true {
		t.Fatalf("auto did not fall back from HTTP to working HTTPS: %#v", result)
	}
}

func TestJungleHappyScanReturnsTerminalResultWithoutPolling(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"code":"000000","message":"ok"}`)
	}))
	defer target.Close()
	scanner := newTestServer(t, target)
	defer scanner.Close()
	targetURL, _ := url.Parse(target.URL)
	raw := fmt.Sprintf("GET /api/user HTTP/1.1\r\nHost: %s\r\n\r\n", targetURL.Host)
	body, _ := json.Marshal(map[string]any{"http": raw, "scan_type": []string{"sensitive_data"}})
	response, err := http.Post(scanner.URL+"/api/v1/jungle_happy_scan", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result struct {
		Scan     map[string]any `json:"scan"`
		Findings []any          `json:"findings"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || result.Scan["status"] != "completed" {
		t.Fatalf("unexpected synchronous result: status=%d payload=%#v", response.StatusCode, result)
	}
	if result.Findings == nil || len(result.Findings) != 0 {
		t.Fatalf("no findings must be encoded as an empty array: %#v", result.Findings)
	}
	coverage := result.Scan["coverage"].(map[string]any)
	if len(coverage["plugins"].(map[string]any)) != 1 {
		t.Fatalf("custom scan_type must select only the requested plugin: %#v", coverage)
	}

	invalidBody, _ := json.Marshal(map[string]any{
		"http": raw, "scan_type": []string{"normal"}, "scheme": "auto", "mode": "deep",
	})
	invalidResponse, err := http.Post(scanner.URL+"/api/v1/jungle_happy_scan", "application/json", bytes.NewReader(invalidBody))
	if err != nil {
		t.Fatal(err)
	}
	defer invalidResponse.Body.Close()
	if invalidResponse.StatusCode != http.StatusBadRequest {
		t.Fatalf("synchronous facade must reject fields other than http/scan_type/scheme: %d", invalidResponse.StatusCode)
	}
}

func TestJungleHappyScanUsesProvidedOriginalResponseAsBaseline(t *testing.T) {
	var requests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "network response")
	}))
	defer target.Close()
	scanner := newTestServer(t, target)
	defer scanner.Close()
	targetURL, _ := url.Parse(target.URL)
	rawRequest := fmt.Sprintf("POST /api/user HTTP/1.1\r\nHost: %s\r\n\r\n", targetURL.Host)
	rawResponse := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Upstream: captured\r\n\r\n<html>原始响应</html>"
	payload, _ := json.Marshal(map[string]any{
		"http": rawRequest, "response": rawResponse, "scheme": "http",
		"scan_type": []string{"security_headers"},
	})
	response, err := http.Post(scanner.URL+"/api/v1/jungle_happy_scan", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result map[string]any
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	scan, _ := result["scan"].(map[string]any)
	findings, _ := result["findings"].([]any)
	connectivity, _ := result["connectivity"].(map[string]any)
	if response.StatusCode != http.StatusOK || scan["status"] != "completed" || connectivity["status_code"] != float64(200) {
		t.Fatalf("provided original response did not complete scan: status=%d payload=%#v", response.StatusCode, result)
	}
	if len(findings) == 0 || requests.Load() != 0 {
		t.Fatalf("scanner did not use the provided response baseline: findings=%d target_requests=%d", len(findings), requests.Load())
	}
}

func TestJungleHappyScanStopsWhenOriginalRequestIsUnreachable(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	unreachableURL, _ := url.Parse(target.URL)
	scanner := newTestServer(t, target)
	target.Close()
	defer scanner.Close()
	raw := fmt.Sprintf("GET /unreachable HTTP/1.1\r\nHost: %s\r\n\r\n", unreachableURL.Host)
	body, _ := json.Marshal(map[string]any{"http": raw, "scan_type": []string{"sensitive_data"}})
	for _, path := range []string{"/api/v1/jungle_happy_scan", "/api/v1/jungle_happy_scan_lite"} {
		response, postErr := http.Post(scanner.URL+path, "application/json", bytes.NewReader(body))
		if postErr != nil {
			t.Fatal(postErr)
		}
		var result map[string]any
		_ = json.NewDecoder(response.Body).Decode(&result)
		_ = response.Body.Close()
		scan := result["scan"].(map[string]any)
		connectivity := result["connectivity"].(map[string]any)
		if response.StatusCode != http.StatusOK || scan["status"] != "failed" || scan["scan_id"] != "" {
			t.Fatalf("unreachable original request must stop before task creation: path=%s payload=%#v", path, result)
		}
		if connectivity["ok"] != false || connectivity["auto_fallback"] != true || connectivity["scheme"] != "https" {
			t.Fatalf("preflight must try HTTP then HTTPS: path=%s connectivity=%#v", path, connectivity)
		}
		if !strings.Contains(scan["error"].(string), "原始报文连通性检测失败") || len(result["findings"].([]any)) != 0 {
			t.Fatalf("preflight failure diagnostics are incomplete: path=%s payload=%#v", path, result)
		}
	}
}

func TestJungleHappyScanPresetResolution(t *testing.T) {
	defaultInput, err := (jungleHappyScanInput{
		HTTP: "GET / HTTP/1.1\r\nHost: bank.test\r\n\r\n",
	}).scanInput()
	if err != nil {
		t.Fatal(err)
	}
	if defaultInput.Mode != "normal" || defaultInput.Scheme != "auto" || len(defaultInput.ScanType) != 9 {
		t.Fatalf("http-only input must use normal/auto defaults: %#v", defaultInput)
	}
	hostInput, err := (jungleHappyScanInput{
		HTTP: "GET / HTTP/1.1\r\nHost: test.icbc.com\r\n\r\n",
		Host: map[string]string{"test.icbc.com": "122.223.22.22"},
	}).scanInput()
	if err != nil || hostInput.Host["test.icbc.com"] != "122.223.22.22" {
		t.Fatalf("host override was not passed to scan input: %#v err=%v", hostInput, err)
	}

	for preset, expected := range map[string]int{"passive": 3, "normal": 9, "deep": 52} {
		input, err := (jungleHappyScanInput{
			HTTP: "GET / HTTP/1.1\r\nHost: bank.test\r\n\r\n", ScanType: []string{preset},
		}).scanInput()
		if err != nil {
			t.Fatal(err)
		}
		if input.Mode != preset || input.Scheme != "auto" || len(input.ScanType) != expected {
			t.Fatalf("unexpected %s preset: %#v", preset, input)
		}
	}
	custom, err := (jungleHappyScanInput{
		HTTP:     "GET / HTTP/1.1\r\nHost: bank.test\r\n\r\n",
		ScanType: []string{"sqli", "error_disclosure"}, Scheme: "http",
	}).scanInput()
	if err != nil {
		t.Fatal(err)
	}
	if custom.Mode != "standard" || custom.Scheme != "http" || len(custom.ScanType) != 2 {
		t.Fatalf("custom plugin selection changed unexpectedly: %#v", custom)
	}
}

func TestJungleHappyScanBase64InputPreservesRawBody(t *testing.T) {
	bodyBytes := []byte{0xd6, 0xd0, 0xce, 0xc4}
	received := make(chan []byte, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		select {
		case received <- body:
		default:
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer target.Close()
	scanner := newTestServer(t, target)
	defer scanner.Close()
	targetURL, _ := url.Parse(target.URL)
	raw := append([]byte(fmt.Sprintf("POST /submit HTTP/1.1\r\nHost: %s\r\nContent-Type: text/plain; charset=gbk\r\nContent-Length: %d\r\n\r\n", targetURL.Host, len(bodyBytes))), bodyBytes...)
	payload, _ := json.Marshal(map[string]any{
		"http_base64": base64.StdEncoding.EncodeToString(raw),
		"scheme":      "http", "scan_type": []string{"sensitive_data"},
	})
	response, err := http.Post(scanner.URL+"/api/v1/jungle_happy_scan", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(response.Body)
		t.Fatalf("base64 scan failed: status=%d body=%s", response.StatusCode, data)
	}
	select {
	case actual := <-received:
		if !bytes.Equal(actual, bodyBytes) {
			t.Fatalf("request body bytes changed: got=%x want=%x", actual, bodyBytes)
		}
	case <-time.After(time.Second):
		t.Fatal("target did not receive request")
	}
}

func TestJungleHappyScanBase64InputValidation(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: bank.test\r\n\r\n"
	valid := base64.StdEncoding.EncodeToString([]byte(raw))
	tests := []struct {
		name  string
		input jungleHappyScanInput
	}{
		{name: "missing", input: jungleHappyScanInput{}},
		{name: "conflict", input: jungleHappyScanInput{HTTP: raw, HTTPBase64: valid}},
		{name: "invalid base64", input: jungleHappyScanInput{HTTPBase64: "%%%"}},
		{name: "empty decoded value", input: jungleHappyScanInput{HTTPBase64: base64.StdEncoding.EncodeToString(nil)}},
		{name: "too large", input: jungleHappyScanInput{HTTPBase64: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'x'}, maxRawHTTPBytes+1))}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.input.scanInput(); err == nil {
				t.Fatal("invalid input was accepted")
			}
		})
	}
	decoded, err := (jungleHappyScanInput{HTTPBase64: valid}).scanInput()
	if err != nil || decoded.HTTP != raw {
		t.Fatalf("valid base64 was not decoded: input=%#v err=%v", decoded, err)
	}
}

func TestJungleHappyScanOriginalResponseValidation(t *testing.T) {
	valid := "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n{\"ok\":true}"
	parsed, present, err := (jungleHappyScanInput{Response: valid}).originalResponse()
	if err != nil || !present || parsed.StatusCode != 201 || parsed.Body == nil ||
		parsed.Header("Content-Type") != "application/json" || len(parsed.HeaderAll("Set-Cookie")) != 2 {
		t.Fatalf("valid original response was not parsed: response=%#v present=%v err=%v", parsed, present, err)
	}
	for _, input := range []jungleHappyScanInput{
		{Response: "not an HTTP response"},
		{Response: "HTTP/1.1 200 OK\r\nX-Test: bad\nvalue\r\n\r\n"},
		{Response: strings.Repeat("x", maxRawHTTPBytes+1)},
	} {
		if _, _, err := input.originalResponse(); err == nil {
			t.Fatalf("invalid original response was accepted: %#v", input)
		}
	}
}

func TestLiteFindingsRemoveRawMessagesWithoutChangingOriginal(t *testing.T) {
	original := []model.Finding{{
		ID: "finding-1",
		Evidence: []model.Evidence{{
			Summary: "matched", Request: "GET /secret HTTP/1.1\r\n\r\n",
			RequestBase64: base64.StdEncoding.EncodeToString([]byte("GET /secret HTTP/1.1\r\n\r\n")),
			Response:      "HTTP/1.1 200 OK\r\n\r\nsecret", ResponseExcerpt: "secret",
		}},
	}}
	lite := liteFindings(original)
	if lite[0].Evidence[0].Request != "" || lite[0].Evidence[0].RequestBase64 != "" || lite[0].Evidence[0].Response != "" {
		t.Fatalf("lite evidence still contains raw messages: %#v", lite)
	}
	if lite[0].Evidence[0].Summary != "matched" || lite[0].Evidence[0].ResponseExcerpt != "secret" {
		t.Fatalf("lite evidence removed fields other than request/response: %#v", lite)
	}
	if original[0].Evidence[0].Request == "" || original[0].Evidence[0].Response == "" {
		t.Fatalf("lite conversion modified original findings: %#v", original)
	}
	if original[0].Evidence[0].RequestBase64 == "" {
		t.Fatalf("lite conversion removed base64 evidence from original findings: %#v", original)
	}
}

func TestJungleHappyScanLiteRoutesAreRegistered(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer target.Close()
	scanner := newTestServer(t, target)
	defer scanner.Close()
	for _, path := range []string{"/api/v1/jungle_happy_scan_lite", "/jungle_happy_scan_lite"} {
		response, err := http.Post(scanner.URL+path, "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("lite route %s is not registered: status=%d", path, response.StatusCode)
		}
	}
}

func TestDedicatedCallbackHandlerAcceptsRegisteredTokenOnly(t *testing.T) {
	store, _ := config.Open(filepath.Join(t.TempDir(), "config.json"))
	callbacks := callback.New()
	defer callbacks.Close()
	manager := engine.NewManager(store, callbacks)
	server, err := New(store, manager, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	token, _ := callbacks.Register("http://127.0.0.1:61166", "xxe")
	mainPort := httptest.NewRecorder()
	server.Handler().ServeHTTP(mainPort, httptest.NewRequest(http.MethodGet, "/api/v1/callback/"+token, nil))
	if mainPort.Code != http.StatusNotFound {
		t.Fatalf("main handler exposed callback route: %d", mainPort.Code)
	}
	recorder := httptest.NewRecorder()
	server.CallbackHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/callback/"+token, nil))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), token) ||
		!strings.Contains(recorder.Body.String(), callback.ResponseMarker(token)) {
		t.Fatalf("dedicated callback handler did not accept token: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	management := httptest.NewRecorder()
	server.CallbackHandler().ServeHTTP(management, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if management.Code != http.StatusNotFound {
		t.Fatalf("callback listener exposed management route: %d", management.Code)
	}

	postToken, _ := callbacks.Register("http://127.0.0.1:61166", "xxe")
	post := httptest.NewRecorder()
	server.CallbackHandler().ServeHTTP(post, httptest.NewRequest(
		http.MethodPost, "/api/v1/callback/"+postToken+"/openapi/v1/envs/apps/1", strings.NewReader(`{"probe":true}`),
	))
	if post.Code != http.StatusOK || !strings.Contains(post.Body.String(), callback.ResponseMarker(postToken)) {
		t.Fatalf("callback POST with appended business path was not accepted: status=%d body=%q", post.Code, post.Body.String())
	}
	if !callbacks.Wait(context.Background(), postToken, time.Second) {
		t.Fatal("callback POST did not reach the one-time registry")
	}
	queryToken, _ := callbacks.Register("http://127.0.0.1:61166", "ssrf")
	query := httptest.NewRecorder()
	server.CallbackHandler().ServeHTTP(query, httptest.NewRequest(http.MethodGet, "/callback?token="+queryToken, nil))
	if query.Code != http.StatusOK {
		t.Fatalf("callback token in query was not accepted: status=%d body=%q", query.Code, query.Body.String())
	}
	unsupported := httptest.NewRecorder()
	server.CallbackHandler().ServeHTTP(unsupported, httptest.NewRequest(http.MethodPut, "/api/v1/callback/"+queryToken, nil))
	if unsupported.Code != http.StatusMethodNotAllowed || unsupported.Header().Get("Allow") != "GET, HEAD, POST" {
		t.Fatalf("unsupported callback method was not rejected: status=%d allow=%q", unsupported.Code, unsupported.Header().Get("Allow"))
	}
}

func newTestServer(t *testing.T, target *httptest.Server) *httptest.Server {
	return newTestServerScheme(t, target, "http")
}

func newTestServerScheme(t *testing.T, target *httptest.Server, defaultScheme string) *httptest.Server {
	return newTestServerWithConfig(t, target, defaultScheme, nil)
}

func newTestServerWithConfig(t *testing.T, target *httptest.Server, defaultScheme string, configure func(*config.Config)) *httptest.Server {
	t.Helper()
	store, err := config.Open(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := store.Get()
	cfg.DefaultScheme = defaultScheme
	cfg.BaselineSamples = 1
	cfg.RequestsPerSecond = 500
	cfg.MaxConcurrency = 8
	cfg.VerifyTLS = false
	parsed, _ := url.Parse(target.URL)
	cfg.AllowedHosts = []string{parsed.Hostname()}
	if configure != nil {
		configure(&cfg)
	}
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	manager := engine.NewManager(store, callback.New())
	server, err := New(store, manager, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(server.Handler())
}

func waitResult(t *testing.T, baseURL, id string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		response, err := http.Get(baseURL + "/api/v1/scans/" + id + "/result")
		if err != nil {
			t.Fatal(err)
		}
		var result map[string]any
		_ = json.NewDecoder(response.Body).Decode(&result)
		_ = response.Body.Close()
		scan := result["scan"].(map[string]any)
		if scan["status"] == "completed" || scan["status"] == "failed" {
			if scan["status"] == "failed" {
				t.Fatalf("scan failed: %#v", scan)
			}
			return result
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("scan did not finish")
	return nil
}
