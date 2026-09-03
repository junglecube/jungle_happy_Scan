package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

func TestTransportCarriesRequestScopedClientCertificate(t *testing.T) {
	cfg := config.Default()
	certificate := &tls.Certificate{Certificate: [][]byte{{1, 2, 3}}}
	client, err := NewWithGovernorAndCertificate(cfg, Hooks{}, nil, certificate)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	httpTransport := client.http.Transport.(*http.Transport)
	if len(httpTransport.TLSClientConfig.Certificates) != 1 ||
		len(httpTransport.TLSClientConfig.Certificates[0].Certificate) != 1 {
		t.Fatalf("request-scoped client certificate missing from TLS config: %#v", httpTransport.TLSClientConfig)
	}
}

func TestTransportPreservesRepeatedResponseHeaders(t *testing.T) {
	source := http.Header{}
	source.Add("Set-Cookie", "a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT")
	source.Add("Set-Cookie", "b=2; HttpOnly")
	headers, headerValues := responseHeaderMaps(source)
	response := model.Response{Headers: headers, HeaderValues: headerValues}
	if values := response.HeaderAll("Set-Cookie"); len(values) != 2 || values[0] == values[1] {
		t.Fatalf("Set-Cookie values = %#v", values)
	}
	if !strings.Contains(response.Header("Set-Cookie"), "Expires=Wed, 21 Oct 2026") {
		t.Fatalf("flattened compatibility header = %q", response.Header("Set-Cookie"))
	}
}

func TestTransportCompletesMutualTLSHandshake(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(731),
		Subject:      pkix.Name{CommonName: "jungle-happy-scan-mtls"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	rawCertificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	clientCertificate := &tls.Certificate{Certificate: [][]byte{rawCertificate}, PrivateKey: key}
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
			http.Error(w, "missing client identity", http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, "mtls-ok")
	}))
	target.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAnyClientCert}
	target.StartTLS()
	defer target.Close()
	parsedURL, _ := url.Parse(target.URL)
	cfg := config.Default()
	cfg.VerifyTLS = false
	cfg.AllowedHosts = []string{parsedURL.Hostname()}
	client, err := NewWithGovernorAndCertificate(cfg, Hooks{}, nil, clientCertificate)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	request, err := httpraw.Parse("GET / HTTP/1.1\r\nHost: "+parsedURL.Host+"\r\n\r\n", "https")
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Send(context.Background(), request)
	if err != nil || response.StatusCode != http.StatusOK || string(response.Body) != "mtls-ok" {
		t.Fatalf("mutual TLS request failed: status=%d body=%q err=%v", response.StatusCode, response.Body, err)
	}
}

func TestDefaultTLSPolicyAllowsIntranetSelfSignedTargets(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "tls-ok")
	}))
	defer target.Close()
	parsedURL, err := url.Parse(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"normalized", "force_http1"} {
		t.Run(mode, func(t *testing.T) {
			cfg := config.Default()
			cfg.TransportMode = mode
			cfg.AllowedHosts = []string{parsedURL.Hostname()}
			client, err := New(cfg, Hooks{})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			request, err := httpraw.Parse("GET / HTTP/1.1\r\nHost: "+parsedURL.Host+"\r\n\r\n", "https")
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Send(context.Background(), request)
			if err != nil || response.StatusCode != http.StatusOK || string(response.Body) != "tls-ok" {
				t.Fatalf("default intranet TLS policy failed: status=%d body=%q err=%v", response.StatusCode, response.Body, err)
			}
		})
	}
}

func TestStrictTLSPolicyRejectsSelfSignedTarget(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "tls-ok")
	}))
	defer target.Close()
	parsedURL, err := url.Parse(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.VerifyTLS = true
	cfg.AllowedHosts = []string{parsedURL.Hostname()}
	client, err := New(cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	request, err := httpraw.Parse("GET / HTTP/1.1\r\nHost: "+parsedURL.Host+"\r\n\r\n", "https")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Send(context.Background(), request); err == nil {
		t.Fatal("strict TLS policy unexpectedly accepted a self-signed target")
	}
}

func TestReadResponseBodyTruncatesDrainsAndReportsFullLength(t *testing.T) {
	original := bytes.Repeat([]byte("x"), 25_000)
	reader := bytes.NewReader(original)
	body, rawBytes, truncated, err := readResponseBody(reader, 10_000, int64(len(original)))
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != 10_000 || rawBytes != int64(len(original)) || !truncated || reader.Len() != 0 {
		t.Fatalf("unexpected bounded read: retained=%d raw=%d truncated=%v remaining=%d", len(body), rawBytes, truncated, reader.Len())
	}
}

func TestInvalidTargetDoesNotConsumeRequestBudget(t *testing.T) {
	cfg := config.Default()
	cfg.AllowedHosts = []string{"allowed.test"}
	cfg.MaxRequests = 1
	cfg.RequestsPerSecond = 500
	client, err := New(cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	request, err := httpraw.Parse("GET / HTTP/1.1\r\nHost: denied.test\r\n\r\n", "http")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Send(context.Background(), request); err == nil {
		t.Fatal("disallowed target unexpectedly succeeded")
	}
	if got := client.sent.Load(); got != 0 {
		t.Fatalf("validation failure consumed request budget: %d", got)
	}
}

func TestTaskSemaphoreWaitDoesNotOccupyGovernor(t *testing.T) {
	cfg := config.Default()
	cfg.AllowedHosts = []string{"127.0.0.1"}
	cfg.MaxConcurrency = 1
	cfg.RequestsPerSecond = 500
	governor := NewGovernor(1, 1, 500)
	client, err := NewWithGovernor(cfg, Hooks{}, governor)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.semaphore <- struct{}{}
	defer func() { <-client.semaphore }()
	request, err := httpraw.Parse("GET / HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n", "http")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := client.Send(ctx, request); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected task semaphore timeout, got %v", err)
	}
	governor.mu.Lock()
	hosts := len(governor.hosts)
	global := len(governor.global)
	governor.mu.Unlock()
	if hosts != 0 || global != 0 || client.sent.Load() != 0 {
		t.Fatalf("task wait leaked outer capacity: hosts=%d global=%d sent=%d", hosts, global, client.sent.Load())
	}
}

func TestTruncatedResponseKeepsConnectionReusable(t *testing.T) {
	var connections atomic.Int32
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("j"), 25_000))
	}))
	target.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	target.Start()
	defer target.Close()
	parsed, _ := url.Parse(target.URL)
	cfg := config.Default()
	cfg.AllowedHosts = []string{parsed.Hostname()}
	cfg.MaxResponseBytes = 10_000
	cfg.RequestsPerSecond = 500
	client, err := New(cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	request, err := httpraw.Parse(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", parsed.Host), "http")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		response, sendErr := client.Send(context.Background(), request)
		if sendErr != nil {
			t.Fatal(sendErr)
		}
		if !response.Truncated || len(response.Body) != 10_000 || response.RawBytes != 25_000 {
			t.Fatalf("unexpected response bounds: truncated=%v retained=%d raw=%d", response.Truncated, len(response.Body), response.RawBytes)
		}
	}
	if got := connections.Load(); got != 1 {
		t.Fatalf("truncated response prevented keep-alive reuse: connections=%d", got)
	}
}

func TestRateLimiterAllowsConfiguredConcurrencyBurst(t *testing.T) {
	limiter := newRateLimiter(10, 8)
	started := time.Now()
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := limiter.Wait(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("initial concurrent burst was serialized: %s", elapsed)
	}
}

func TestFriendlyNetworkErrors(t *testing.T) {
	if !IsHTTPToHTTPSMismatch(errors.New("http: server gave HTTP response to HTTPS client")) {
		t.Fatal("HTTPS/HTTP mismatch was not recognized")
	}
	message := FriendlyError(context.DeadlineExceeded, 17)
	if !strings.Contains(message, "17 秒") || !strings.Contains(message, "提高") {
		t.Fatalf("timeout guidance is not actionable: %q", message)
	}
}

func TestHTTPResponseToHTTPSMismatchDetection(t *testing.T) {
	if !IsHTTPResponseToHTTPSMismatch(model.Response{StatusCode: 400, Body: []byte("Client sent an HTTP request to an HTTPS server.")}) {
		t.Fatal("HTTP-to-HTTPS 400 response was not recognized")
	}
	if IsHTTPResponseToHTTPSMismatch(model.Response{StatusCode: 400, Body: []byte(`{"error":"invalid request"}`)}) {
		t.Fatal("ordinary application 400 must not trigger HTTPS fallback")
	}
}

func TestRawHTTP1PreservesDuplicateHeaders(t *testing.T) {
	var protocol string
	var duplicateValues []string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protocol = r.Proto
		duplicateValues = r.Header.Values("X-Duplicate")
		_, _ = io.WriteString(w, "raw-ok")
	}))
	defer target.Close()
	parsed, _ := url.Parse(target.URL)
	cfg := config.Default()
	cfg.DefaultScheme = "http"
	cfg.TransportMode = "raw_http1"
	cfg.AllowedHosts = []string{parsed.Hostname()}
	cfg.RequestsPerSecond = 500
	client, err := New(cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	request, err := httpraw.Parse(fmt.Sprintf(
		"POST /raw HTTP/1.1\r\nHost: %s\r\nX-Duplicate: one\r\nX-Duplicate: two\r\nContent-Type: text/plain\r\n\r\npayload",
		parsed.Host,
	), "http")
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Send(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || protocol != "HTTP/1.1" ||
		len(duplicateValues) != 2 || duplicateValues[0] != "one" || duplicateValues[1] != "two" {
		t.Fatalf("raw mode lost protocol fidelity: status=%d proto=%s values=%#v", response.StatusCode, protocol, duplicateValues)
	}
}

func TestDirectTransportIgnoresEnvironmentProxyAndUsesPinnedDNS(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "pinned-ok")
	}))
	defer target.Close()
	parsed, _ := url.Parse(target.URL)
	_, port, _ := net.SplitHostPort(parsed.Host)
	cfg := config.Default()
	cfg.DefaultScheme = "http"
	cfg.AllowedHosts = []string{"pinned.jungle-happy-scan.invalid"}
	cfg.RequestsPerSecond = 500
	cfg.VerifyTLS = false
	client, err := New(cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	transport := client.http.Transport.(*http.Transport)
	if transport.Proxy != nil {
		t.Fatal("direct transport must not inherit environment proxy")
	}
	client.dnsCache["pinned.jungle-happy-scan.invalid"] = []net.IP{net.ParseIP("127.0.0.1")}
	raw, err := httpraw.Parse(fmt.Sprintf("GET / HTTP/1.1\r\nHost: pinned.jungle-happy-scan.invalid:%s\r\n\r\n", port), "http")
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Send(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if response.Text() != "pinned-ok" {
		t.Fatalf("unexpected response %q", response.Text())
	}
}

func TestHostOverrideConnectsToPinnedIPAndPreservesHost(t *testing.T) {
	var receivedHost string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHost = r.Host
		_, _ = io.WriteString(w, "override-ok")
	}))
	defer target.Close()
	parsed, _ := url.Parse(target.URL)
	_, port, _ := net.SplitHostPort(parsed.Host)
	cfg := config.Default()
	cfg.AllowedHosts = []string{"test.icbc.com"}
	cfg.HostOverrides = map[string]string{"test.icbc.com": "127.0.0.1"}
	cfg.RequestsPerSecond = 500
	client, err := New(cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	raw, _ := httpraw.Parse(fmt.Sprintf("GET / HTTP/1.1\r\nHost: test.icbc.com:%s\r\n\r\n", port), "http")
	response, err := client.Send(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if response.Text() != "override-ok" || receivedHost != "test.icbc.com:"+port {
		t.Fatalf("host override changed HTTP authority: response=%q host=%q", response.Text(), receivedHost)
	}
}

func TestExplicitProxyIsEnabled(t *testing.T) {
	cfg := config.Default()
	cfg.ProxyURL = "http://127.0.0.1:8081"
	client, err := New(cfg, Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if client.http.Transport.(*http.Transport).Proxy == nil {
		t.Fatal("explicit proxy was not enabled")
	}
}
