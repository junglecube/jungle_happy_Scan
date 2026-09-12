package signing

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

func TestHTTPSignerReplacesSignatureAndPreservesRequestIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("unexpected request content type: %q", got)
		}
		var envelope signatureEnvelope
		if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
			t.Fatalf("signer received invalid JSON: %v", err)
		}
		encoded := []byte(envelope.Request)
		raw, err := base64.StdEncoding.Strict().DecodeString(string(encoded))
		if err != nil {
			t.Fatalf("signer received invalid base64: %v", err)
		}
		updated := strings.Replace(string(raw), "X-Signature: old", "X-Signature: new", 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(signatureEnvelope{Request: base64.StdEncoding.EncodeToString([]byte(updated))})
	}))
	defer server.Close()

	signer, err := New(&model.SignatureInput{Mode: "http", Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	request, err := httpraw.Parse("POST /submit HTTP/1.1\r\nHost: example.test\r\nX-Signature: old\r\n\r\nvalue", "http")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Header("X-Signature") != "new" || signed.Method != request.Method || signed.Target != request.Target || signed.Host() != request.Host() {
		t.Fatalf("unexpected signed request: %#v", signed)
	}
}

func TestSignerRejectsChangedRequestIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var envelope signatureEnvelope
		_ = json.NewDecoder(r.Body).Decode(&envelope)
		raw, _ := base64.StdEncoding.Strict().DecodeString(envelope.Request)
		changed := strings.Replace(string(raw), "POST /submit", "GET /other", 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(signatureEnvelope{Request: base64.StdEncoding.EncodeToString([]byte(changed))})
	}))
	defer server.Close()
	signer, err := New(&model.SignatureInput{Mode: "http", Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	request, _ := httpraw.Parse("POST /submit HTTP/1.1\r\nHost: example.test\r\n\r\n", "http")
	if _, err := signer.Sign(context.Background(), request); err == nil || !strings.Contains(err.Error(), "不能修改") {
		t.Fatalf("changed request identity was accepted: %v", err)
	}
}

func TestHTTPSignerRejectsNonJSONResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, base64.StdEncoding.EncodeToString([]byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")))
	}))
	defer server.Close()
	signer, err := New(&model.SignatureInput{Mode: "http", Endpoint: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	request, _ := httpraw.Parse("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n", "http")
	if _, err := signer.Sign(context.Background(), request); err == nil || !strings.Contains(err.Error(), "不是合法 JSON") {
		t.Fatalf("non-JSON response was accepted: %v", err)
	}
}

func TestLocalSignerUsesConfiguredRuntimeAndScript(t *testing.T) {
	dir := t.TempDir()
	output, _ := httpraw.Parse("GET /signed HTTP/1.1\r\nHost: example.test\r\nX-Signature: local\r\n\r\n", "http")
	encoded := base64.StdEncoding.EncodeToString(output.RawExact())
	script := filepath.Join(dir, "signer.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s' \""+encoded+"\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	signer, err := New(&model.SignatureInput{Mode: "local_js", Runtime: "/bin/sh", Script: script})
	if err != nil {
		t.Fatal(err)
	}
	request, _ := httpraw.Parse("GET /signed HTTP/1.1\r\nHost: example.test\r\nX-Signature: local\r\n\r\n", "http")
	if _, err := signer.Sign(context.Background(), request); err != nil {
		t.Fatal(err)
	}
}

func TestNewValidatesSignatureMode(t *testing.T) {
	if _, err := New(&model.SignatureInput{Mode: "http", Endpoint: "not-a-url"}); err == nil {
		t.Fatal("invalid HTTP endpoint was accepted")
	}
	if _, err := New(&model.SignatureInput{Mode: "other"}); err == nil {
		t.Fatal("invalid signature mode was accepted")
	}
	if _, err := New(&model.SignatureInput{Mode: "http", Endpoint: (&url.URL{Scheme: "ftp", Host: "example.test"}).String()}); err == nil {
		t.Fatal("unsupported endpoint scheme was accepted")
	}
}
