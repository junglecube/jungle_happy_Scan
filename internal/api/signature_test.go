package api

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
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
