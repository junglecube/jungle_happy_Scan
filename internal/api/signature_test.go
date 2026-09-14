package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jungle_happy_Scan/internal/callback"
	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/engine"
	"jungle_happy_Scan/internal/model"
)

func TestSignatureScriptUploadPreservesFilename(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer target.Close()
	scanner := newTestServer(t, target)
	defer scanner.Close()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "F-PMC.js")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(part, "console.log('signer')")
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest(http.MethodPost, scanner.URL+"/api/v1/signature-files", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result map[string]any
	_ = json.NewDecoder(response.Body).Decode(&result)
	path, _ := result["signature_script"].(string)
	if response.StatusCode != http.StatusCreated || filepath.Base(path) != "F-PMC.js" {
		t.Fatalf("signature script upload failed: status=%d result=%#v", response.StatusCode, result)
	}
}

func TestResolveSignatureApp(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "FS_PMC.js"), []byte("console.log('signer')"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := &Server{signatureDir: dir}
	input := model.ScanInput{SignatureAppName: "fs_pmc"}
	if err := server.resolveSignatureApp(&input); err != nil {
		t.Fatal(err)
	}
	if input.Signature == nil || input.Signature.Mode != "local_js" || filepath.Base(input.Signature.Script) != "FS_PMC.js" {
		t.Fatalf("application name was not mapped to its fixed script: %#v", input)
	}

	if err := server.resolveSignatureApp(&model.ScanInput{SignatureAppName: "../FS_PMC"}); err == nil || !strings.Contains(err.Error(), "不能包含路径") {
		t.Fatalf("unsafe application name was accepted: %v", err)
	}
	if err := server.resolveSignatureApp(&model.ScanInput{SignatureAppName: "missing"}); err == nil || !strings.Contains(err.Error(), "未找到") {
		t.Fatalf("missing application name was accepted: %v", err)
	}
	if err := server.resolveSignatureApp(&model.ScanInput{SignatureAppName: "FS_PMC", Signature: &model.SignatureInput{Mode: "http", Endpoint: "http://example.test"}}); err == nil || !strings.Contains(err.Error(), "不能同时") {
		t.Fatalf("ambiguous signature input was accepted: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fs_pmc.js"), []byte("console.log('other')"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := server.resolveSignatureApp(&model.ScanInput{SignatureAppName: "FS_PMC"}); err == nil || !strings.Contains(err.Error(), "多个脚本") {
		t.Fatalf("case-insensitive ambiguity was accepted: %v", err)
	}
}

func TestSignatureApplicationsListsOnlySafeUnambiguousNames(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"FS-PMC.js", "F-ORDER.js", "README.txt", "fs-pmc.js"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("// test"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	server := &Server{signatureDir: dir}
	recorder := httptest.NewRecorder()
	server.signatureApplications(recorder, httptest.NewRequest(http.MethodGet, "/api/v2/signature-applications", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", recorder.Code)
	}
	var result struct {
		APIVersion string `json:"api_version"`
		Items      []struct {
			AppName string `json:"app_name"`
		} `json:"items"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.APIVersion != "2.0" || len(result.Items) != 1 || result.Items[0].AppName != "F-ORDER" {
		t.Fatalf("unexpected signature applications: %#v", result)
	}
}

func TestConnectivityAcceptsSignatureAppName(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer target.Close()
	parsed, err := url.Parse(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	store, err := config.Open(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := store.Get()
	cfg.DefaultScheme = "http"
	cfg.AllowedHosts = []string{parsed.Hostname()}
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	server, err := New(store, engine.NewManager(store, callback.New()), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := os.MkdirAll(server.signatureDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(server.signatureDir, "FS_PMC.js"), []byte("process.stdout.write(process.argv[3])"), 0o600); err != nil {
		t.Fatal(err)
	}
	scanner := httptest.NewServer(server.Handler())
	defer scanner.Close()

	payload, _ := json.Marshal(map[string]any{
		"http":               "GET / HTTP/1.1\r\nHost: " + parsed.Host + "\r\n\r\n",
		"scheme":             "http",
		"signature_app_name": "fs_pmc",
	})
	response, err := http.Post(scanner.URL+"/api/v1/connectivity", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result map[string]any
	_ = json.NewDecoder(response.Body).Decode(&result)
	if response.StatusCode != http.StatusOK || result["ok"] != true {
		t.Fatalf("signature_app_name connectivity request failed: status=%d result=%#v", response.StatusCode, result)
	}
}
