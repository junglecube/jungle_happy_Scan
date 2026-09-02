package transport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
	"jungle_happy_Scan/internal/responsebody"
)

type Hooks struct {
	OnRequest func()
	OnError   func()
}

type Client struct {
	cfg               config.Config
	http              *http.Client
	semaphore         chan struct{}
	limiter           *rateLimiter
	hooks             Hooks
	sent              atomic.Int64
	mu                sync.Mutex
	dnsCache          map[string][]net.IP
	governor          *Governor
	clientCertificate *tls.Certificate
}

func New(cfg config.Config, hooks Hooks) (*Client, error) {
	return NewWithGovernor(cfg, hooks, nil)
}

func NewWithGovernor(cfg config.Config, hooks Hooks, governor *Governor) (*Client, error) {
	return NewWithGovernorAndCertificate(cfg, hooks, governor, nil)
}

func NewWithGovernorAndCertificate(cfg config.Config, hooks Hooks, governor *Governor, certificate *tls.Certificate) (*Client, error) {
	dialer := &net.Dialer{Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second, KeepAlive: 30 * time.Second}
	client := &Client{
		cfg: cfg, semaphore: make(chan struct{}, cfg.MaxConcurrency),
		limiter: newRateLimiter(cfg.RequestsPerSecond, cfg.MaxConcurrency), hooks: hooks, dnsCache: make(map[string][]net.IP), governor: governor,
		clientCertificate: certificate,
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: !cfg.VerifyTLS} // #nosec G402 -- admin-controlled test setting
	if certificate != nil {
		tlsConfig.Certificates = []tls.Certificate{*certificate}
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           client.dialContext,
		ForceAttemptHTTP2:     cfg.TransportMode == "normalized",
		MaxIdleConns:          cfg.MaxConcurrency * 4,
		MaxIdleConnsPerHost:   cfg.MaxConcurrency,
		MaxConnsPerHost:       cfg.MaxConcurrency,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   time.Duration(cfg.TimeoutSeconds) * time.Second,
		ResponseHeaderTimeout: time.Duration(cfg.TimeoutSeconds) * time.Second,
		TLSClientConfig:       tlsConfig,
	}
	if cfg.TransportMode == "force_http1" {
		transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	if cfg.ProxyURL != "" {
		proxyURL, err := url.Parse(cfg.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("代理地址无效: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
		// 显式代理由管理员信任；目标 DNS 解析发生在代理侧，无法在本地固定目标 IP。
		transport.DialContext = dialer.DialContext
	}
	client.http = &http.Client{
		Transport: transport,
		Timeout:   time.Duration(cfg.TimeoutSeconds) * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return client, nil
}

func (c *Client) Close() { c.http.CloseIdleConnections() }

func (c *Client) Send(ctx context.Context, raw *httpraw.Request) (model.Response, error) {
	return c.send(ctx, raw, 3)
}

func (c *Client) SendWithSchemeFallback(ctx context.Context, raw *httpraw.Request, automatic bool) (model.Response, *httpraw.Request, bool, error) {
	response, err := c.Send(ctx, raw)
	if err == nil {
		if !automatic || raw.Scheme != "http" || !IsHTTPResponseToHTTPSMismatch(response) {
			return response, raw, false, nil
		}
		fallback := raw.WithScheme("https")
		response, err = c.Send(ctx, fallback)
		return response, fallback, true, err
	}
	if !automatic || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) && ctx.Err() != nil {
		return response, raw, false, err
	}
	alternateScheme := "http"
	if raw.Scheme == "http" {
		alternateScheme = "https"
	}
	fallback := raw.WithScheme(alternateScheme)
	response, err = c.Send(ctx, fallback)
	return response, fallback, true, err
}

// IsHTTPResponseToHTTPSMismatch detects the common 400 response returned by
// TLS listeners and reverse proxies when they receive a plain HTTP request.
// Ordinary application-level 400 responses must not trigger a protocol retry.
func IsHTTPResponseToHTTPSMismatch(response model.Response) bool {
	if response.StatusCode != http.StatusBadRequest {
		return false
	}
	message := strings.ToLower(string(response.Body))
	return strings.Contains(message, "client sent an http request to an https server") ||
		strings.Contains(message, "plain http request was sent to https port") ||
		strings.Contains(message, "the plain http request was sent to https port")
}

func IsHTTPToHTTPSMismatch(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "server gave http response to https client") ||
		strings.Contains(message, "http response to https client") ||
		strings.Contains(message, "first record does not look like a tls handshake")
}

func FriendlyError(err error, timeoutSeconds int) string {
	if err == nil {
		return ""
	}
	if IsHTTPToHTTPSMismatch(err) {
		return "目标端口返回 HTTP，但当前按 HTTPS 连接。请选择“自动”或“HTTP”协议后重试。"
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return fmt.Sprintf("等待目标响应超时（当前 %d 秒）。请确认目标可达，或在配置页面提高“请求超时”。", timeoutSeconds)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Sprintf("等待目标响应超时（当前 %d 秒）。请确认目标可达，或在配置页面提高“请求超时”。", timeoutSeconds)
	}
	return err.Error()
}

func (c *Client) send(ctx context.Context, raw *httpraw.Request, redirectsLeft int) (model.Response, error) {
	transformed, err := httpraw.ApplyRequestTransforms(raw, c.cfg.RequestTransforms)
	if err != nil {
		return model.Response{}, fmt.Errorf("应用动态请求规则失败: %w", err)
	}
	raw = transformed
	requestURL, err := raw.URL()
	if err != nil {
		return model.Response{}, err
	}
	parsed, err := url.Parse(requestURL)
	if err != nil {
		return model.Response{}, err
	}
	if err := c.validateTarget(ctx, parsed.Hostname()); err != nil {
		return model.Response{}, err
	}
	// Fast rejection avoids waiting on any limiter once the task budget is
	// already exhausted. reserveRequest performs the final race-safe check next
	// to the actual write.
	if c.sent.Load() >= int64(c.cfg.MaxRequests) {
		return model.Response{}, errors.New("扫描请求数量已达到 max_requests 上限")
	}
	// Acquire from the narrowest scope outwards. A busy task must not reserve a
	// process/target slot while it is still waiting for its own semaphore.
	select {
	case c.semaphore <- struct{}{}:
		defer func() { <-c.semaphore }()
	case <-ctx.Done():
		return model.Response{}, ctx.Err()
	}
	if err := c.limiter.Wait(ctx); err != nil {
		return model.Response{}, err
	}
	releaseGlobal, err := c.governor.Acquire(ctx, parsed.Hostname())
	if err != nil {
		return model.Response{}, err
	}
	defer releaseGlobal()
	if c.cfg.TransportMode == "raw_http1" {
		return c.sendRawHTTP1(ctx, raw, parsed, requestURL, redirectsLeft)
	}
	request, err := http.NewRequestWithContext(ctx, raw.Method, requestURL, bytes.NewReader(raw.Body))
	if err != nil {
		return model.Response{}, err
	}
	request.Header = raw.TransportHeaders()
	// Let net/http negotiate and transparently decompress gzip. Preserving a
	// browser-supplied Accept-Encoding would otherwise return compressed bytes
	// to the scanner while raw HTTP/1 mode already requests identity.
	request.Header.Del("Accept-Encoding")
	request.Host = raw.Authority()
	if !c.reserveRequest() {
		return model.Response{}, errors.New("扫描请求数量已达到 max_requests 上限")
	}
	if c.hooks.OnRequest != nil {
		c.hooks.OnRequest()
	}
	start := time.Now()
	response, err := c.http.Do(request)
	if err != nil {
		if c.hooks.OnError != nil {
			c.hooks.OnError()
		}
		return model.Response{}, err
	}
	defer response.Body.Close()
	body, rawBytes, truncated, readErr := readResponseBody(response.Body, c.cfg.MaxResponseBytes, response.ContentLength)
	if readErr != nil {
		if c.hooks.OnError != nil {
			c.hooks.OnError()
		}
		return model.Response{}, readErr
	}
	headers, headerValues := responseHeaderMaps(response.Header)
	body, charset := responsebody.Decode(body, headers["content-type"])
	result := model.Response{StatusCode: response.StatusCode, Headers: headers, HeaderValues: headerValues, Body: body, Elapsed: time.Since(start), URL: requestURL, Charset: charset, RawBytes: rawBytes, Truncated: truncated}
	location := response.Header.Get("Location")
	if c.cfg.FollowRedirects && redirectsLeft > 0 && response.StatusCode >= 300 && response.StatusCode < 400 && location != "" {
		nextURL, err := parsed.Parse(location)
		if err != nil {
			return result, nil
		}
		next := raw.Clone()
		next.Method = http.MethodGet
		next.Target = nextURL.String()
		next.Body = nil
		next = next.WithoutHeaders("Content-Type", "Content-Length")
		return c.send(ctx, next, redirectsLeft-1)
	}
	return result, nil
}

func (c *Client) sendRawHTTP1(ctx context.Context, raw *httpraw.Request, parsed *url.URL, requestURL string, redirectsLeft int) (model.Response, error) {
	if c.cfg.ProxyURL != "" {
		return model.Response{}, errors.New("raw_http1 模式暂不支持 HTTP 代理")
	}
	address := parsed.Host
	if _, _, err := net.SplitHostPort(address); err != nil {
		port := "80"
		if parsed.Scheme == "https" {
			port = "443"
		}
		address = net.JoinHostPort(parsed.Hostname(), port)
	}
	connection, err := c.dialContext(ctx, "tcp", address)
	if err != nil {
		return model.Response{}, err
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	} else {
		_ = connection.SetDeadline(time.Now().Add(time.Duration(c.cfg.TimeoutSeconds) * time.Second))
	}
	if parsed.Scheme == "https" {
		tlsConfig := &tls.Config{
			ServerName: parsed.Hostname(), MinVersion: tls.VersionTLS12,
			InsecureSkipVerify: !c.cfg.VerifyTLS, // #nosec G402 -- admin-controlled test target
		}
		if c.clientCertificate != nil {
			tlsConfig.Certificates = []tls.Certificate{*c.clientCertificate}
		}
		tlsConnection := tls.Client(connection, tlsConfig)
		if err := tlsConnection.HandshakeContext(ctx); err != nil {
			return model.Response{}, err
		}
		connection = tlsConnection
	}
	target := raw.Target
	if absolute, err := url.Parse(target); err == nil && absolute.IsAbs() {
		target = absolute.RequestURI()
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "%s %s HTTP/1.1\r\n", raw.Method, target)
	hostWritten := false
	for _, header := range raw.Headers {
		lower := strings.ToLower(header.Name)
		switch lower {
		case "content-length", "transfer-encoding", "connection", "accept-encoding":
			continue
		case "host":
			hostWritten = true
		}
		fmt.Fprintf(&builder, "%s: %s\r\n", header.Name, header.Value)
	}
	if !hostWritten {
		fmt.Fprintf(&builder, "Host: %s\r\n", raw.Authority())
	}
	fmt.Fprintf(&builder, "Content-Length: %d\r\n", len(raw.Body))
	builder.WriteString("Accept-Encoding: identity\r\nConnection: close\r\n\r\n")
	if !c.reserveRequest() {
		return model.Response{}, errors.New("扫描请求数量已达到 max_requests 上限")
	}
	if c.hooks.OnRequest != nil {
		c.hooks.OnRequest()
	}
	started := time.Now()
	if _, err := io.WriteString(connection, builder.String()); err != nil {
		return model.Response{}, err
	}
	if _, err := connection.Write(raw.Body); err != nil {
		return model.Response{}, err
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: raw.Method})
	if err != nil {
		if c.hooks.OnError != nil {
			c.hooks.OnError()
		}
		return model.Response{}, err
	}
	defer response.Body.Close()
	body, rawBytes, truncated, err := readResponseBody(response.Body, c.cfg.MaxResponseBytes, response.ContentLength)
	if err != nil {
		return model.Response{}, err
	}
	headers, headerValues := responseHeaderMaps(response.Header)
	body, charset := responsebody.Decode(body, headers["content-type"])
	result := model.Response{StatusCode: response.StatusCode, Headers: headers, HeaderValues: headerValues, Body: body, Elapsed: time.Since(started), URL: requestURL, Charset: charset, RawBytes: rawBytes, Truncated: truncated}
	location := response.Header.Get("Location")
	if c.cfg.FollowRedirects && redirectsLeft > 0 && response.StatusCode >= 300 && response.StatusCode < 400 && location != "" {
		nextURL, err := parsed.Parse(location)
		if err == nil {
			next := raw.ReplaceTarget(nextURL.String())
			return c.send(ctx, next, redirectsLeft-1)
		}
	}
	return result, nil
}

func responseHeaderMaps(source http.Header) (map[string]string, map[string][]string) {
	headers := make(map[string]string, len(source))
	headerValues := make(map[string][]string, len(source))
	for name, values := range source {
		lower := strings.ToLower(name)
		headerValues[lower] = append([]string(nil), values...)
		headers[lower] = strings.Join(values, ", ")
	}
	return headers, headerValues
}

const maxResponseDrainBytes int64 = 4 << 20

// readResponseBody keeps the retained body bounded. When truncation occurs it
// drains a bounded tail so ordinary oversized JSP/JSON responses can still
// reuse their keep-alive connection. RawBytes is the declared full entity size
// when trustworthy, otherwise the number of bytes actually observed.
func readResponseBody(body io.Reader, limit, contentLength int64) ([]byte, int64, bool, error) {
	if limit < 0 {
		limit = 0
	}
	captured, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, int64(len(captured)), false, err
	}
	observed := int64(len(captured))
	truncated := observed > limit
	if truncated {
		captured = captured[:limit]
		// The +1 reveals whether the bounded drain itself was exhausted. Either
		// way these are bytes observed on the wire and belong in the fallback
		// RawBytes count.
		drained, _ := io.Copy(io.Discard, io.LimitReader(body, maxResponseDrainBytes+1))
		observed += drained
	}
	rawBytes := observed
	if contentLength >= observed {
		rawBytes = contentLength
	}
	return captured, rawBytes, truncated, nil
}

func (c *Client) reserveRequest() bool {
	maximum := int64(c.cfg.MaxRequests)
	for {
		used := c.sent.Load()
		if used >= maximum {
			return false
		}
		if c.sent.CompareAndSwap(used, used+1) {
			return true
		}
	}
}

func (c *Client) validateTarget(ctx context.Context, host string) error {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return errors.New("目标 Host 为空")
	}
	if len(c.cfg.AllowedHosts) > 0 {
		allowed := false
		for _, pattern := range c.cfg.AllowedHosts {
			matched, _ := path.Match(strings.ToLower(strings.TrimSpace(pattern)), host)
			if matched {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("目标 %q 不在 allowed_hosts 白名单中", host)
		}
	}
	ips, err := c.lookup(ctx, host)
	if err != nil {
		return err
	}
	if !c.cfg.AllowPrivateTargets {
		for _, ip := range ips {
			if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
				return fmt.Errorf("配置禁止访问私网/保留目标 %s", ip)
			}
		}
	}
	return nil
}

func (c *Client) lookup(ctx context.Context, host string) ([]net.IP, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if override := strings.TrimSpace(c.cfg.HostOverrides[host]); override != "" {
		ip := net.ParseIP(override)
		if ip == nil {
			return nil, fmt.Errorf("目标 %q 的 host 映射不是有效 IP", host)
		}
		return []net.IP{ip}, nil
	}
	c.mu.Lock()
	cached := append([]net.IP(nil), c.dnsCache[host]...)
	c.mu.Unlock()
	if len(cached) > 0 {
		return cached, nil
	}
	if parsed := net.ParseIP(host); parsed != nil {
		return []net.IP{parsed}, nil
	}
	addresses, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("无法解析目标 %q: %w", host, err)
	}
	c.mu.Lock()
	c.dnsCache[host] = append([]net.IP(nil), addresses...)
	c.mu.Unlock()
	return addresses, nil
}

func (c *Client) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("连接地址无效 %q: %w", address, err)
	}
	ips, err := c.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: time.Duration(c.cfg.TimeoutSeconds) * time.Second, KeepAlive: 30 * time.Second}
	var lastErr error
	for _, ip := range ips {
		connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return connection, nil
		}
		lastErr = dialErr
	}
	if lastErr == nil {
		lastErr = errors.New("域名没有可用 IP")
	}
	return nil, fmt.Errorf("连接 %s 失败: %w", address, lastErr)
}

type rateLimiter struct {
	mu         sync.Mutex
	rate       float64
	capacity   float64
	tokens     float64
	lastRefill time.Time
}

func newRateLimiter(rate float64, burst int) *rateLimiter {
	capacity := float64(max(burst, 1))
	return &rateLimiter{
		rate: rate, capacity: capacity, tokens: capacity, lastRefill: time.Now(),
	}
}

func (r *rateLimiter) Wait(ctx context.Context) error {
	for {
		r.mu.Lock()
		now := time.Now()
		r.tokens = min(r.capacity, r.tokens+now.Sub(r.lastRefill).Seconds()*r.rate)
		r.lastRefill = now
		if r.tokens >= 1 {
			r.tokens--
			r.mu.Unlock()
			return nil
		}
		delay := time.Duration((1 - r.tokens) / r.rate * float64(time.Second))
		r.mu.Unlock()
		timer := time.NewTimer(max(delay, time.Millisecond))
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		}
	}
}
