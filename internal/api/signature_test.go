package api

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
