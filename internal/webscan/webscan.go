package webscan

import (
	"bufio"
	"bytes"
	"container/list"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"jungle_happy_Scan/internal/clientcert"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
	"jungle_happy_Scan/internal/responsebody"
)

const (
	maxRequestBytes  = 5_000_000
	maxResponseBytes = 2_000_000
	maxAssets        = 2_000
)

var (
	numericPath = regexp.MustCompile(`^\d+$`)
	uuidPath    = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	hexPath     = regexp.MustCompile(`(?i)^[0-9a-f]{16,}$`)
	staticExt   = map[string]bool{".css": true, ".js": true, ".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true, ".ico": true, ".woff": true, ".woff2": true, ".ttf": true, ".map": true, ".mp4": true, ".webm": true}
	hopHeaders  = map[string]bool{"connection": true, "proxy-connection": true, "keep-alive": true, "proxy-authenticate": true, "proxy-authorization": true, "te": true, "trailer": true, "transfer-encoding": true, "upgrade": true}
)

type Scanner interface {
	Start(model.ScanInput, model.Response) (string, error)
	Snapshot(string) (model.ScanView, []model.Finding, bool)
	Cancel(string) bool
}

type SessionConfig struct {
	Name                 string   `json:"name"`
	TargetURL            string   `json:"target_url"`
	ScopeHosts           []string `json:"scope_hosts"`
	ProxyListen          string   `json:"proxy_listen"`
	ScanMode             string   `json:"scan_mode"`
	Plugins              []string `json:"plugins,omitempty"`
	AutoScan             bool     `json:"auto_scan"`
	FilterStatic         bool     `json:"filter_static"`
	StaticExtensions     []string `json:"static_extensions,omitempty"`
	BrowserOwner         string   `json:"browser_owner,omitempty"`
	InterceptRequests    bool     `json:"intercept_requests"`
	InterceptResponses   bool     `json:"intercept_responses"`
	InterceptTimeout     int      `json:"intercept_timeout_seconds,omitempty"`
	InterceptOnTimeout   string   `json:"intercept_on_timeout,omitempty"`
	MaxPendingIntercepts int      `json:"max_pending_intercepts,omitempty"`
	InterceptTLS         bool     `json:"intercept_tls"`
	ClientTLSFile        string   `json:"client_tls_file,omitempty"`
	ClientTLSPassword    string   `json:"client_tls_password,omitempty"`
}

type Counters struct {
	ObservedRequests int `json:"observed_requests"`
	Assets           int `json:"assets"`
	Queued           int `json:"queued"`
	Scanning         int `json:"scanning"`
	Completed        int `json:"completed"`
	Failed           int `json:"failed"`
	Findings         int `json:"findings"`
	HTTPSTunnels     int `json:"https_tunnels"`
}

type SiteFinding struct {
	model.Finding
	WebScanID       string `json:"web_scan_id,omitempty"`
	AssetID         string `json:"asset_id"`
	InterfaceMethod string `json:"interface_method"`
	InterfaceHost   string `json:"interface_host"`
	InterfacePath   string `json:"interface_path"`
}

type HistoricalAsset struct {
	Asset
	WebScanID string `json:"web_scan_id"`
}

type FindingGroup struct {
	Key        string `json:"key"`
	PluginID   string `json:"plugin_id"`
	Title      string `json:"title"`
	Count      int    `json:"count"`
	Interfaces int    `json:"interfaces"`
}

type SessionView struct {
	ID                   string        `json:"id"`
	Name                 string        `json:"name"`
	TargetURL            string        `json:"target_url"`
	ScopeHosts           []string      `json:"scope_hosts"`
	GlobalScope          bool          `json:"global_scope"`
	OutOfScopePolicy     string        `json:"out_of_scope_policy"`
	ProxyListen          string        `json:"proxy_listen"`
	ScanMode             string        `json:"scan_mode"`
	Plugins              []string      `json:"plugins"`
	AutoScan             bool          `json:"auto_scan"`
	FilterStatic         bool          `json:"filter_static"`
	StaticExtensions     []string      `json:"static_extensions,omitempty"`
	BrowserOwner         string        `json:"browser_owner,omitempty"`
	InterceptRequests    bool          `json:"intercept_requests"`
	InterceptResponses   bool          `json:"intercept_responses"`
	InterceptTimeout     int           `json:"intercept_timeout_seconds"`
	InterceptOnTimeout   string        `json:"intercept_on_timeout"`
	MaxPendingIntercepts int           `json:"max_pending_intercepts"`
	InterceptTLS         bool          `json:"intercept_tls"`
	ClientTLSFile        string        `json:"client_tls_file,omitempty"`
	Status               string        `json:"status"`
	CreatedAt            time.Time     `json:"created_at"`
	Revision             uint64        `json:"revision"`
	AssetRevision        uint64        `json:"asset_revision"`
	ProgressRevision     uint64        `json:"progress_revision"`
	FindingRevision      uint64        `json:"finding_revision"`
	InterceptionRevision uint64        `json:"interception_revision"`
	LastError            string        `json:"last_error,omitempty"`
	Counters             Counters      `json:"counters"`
	Findings             []SiteFinding `json:"findings,omitempty"`
}

type Asset struct {
	ID              string          `json:"id"`
	Fingerprint     string          `json:"fingerprint"`
	Method          string          `json:"method"`
	Host            string          `json:"host"`
	Path            string          `json:"path"`
	NormalizedPath  string          `json:"normalized_path"`
	ContentType     string          `json:"content_type,omitempty"`
	SeenCount       int             `json:"seen_count"`
	FirstSeen       time.Time       `json:"first_seen"`
	LastSeen        time.Time       `json:"last_seen"`
	ResponseStatus  int             `json:"response_status,omitempty"`
	ResponseBytes   int64           `json:"response_bytes,omitempty"`
	RawRequest      string          `json:"raw_request,omitempty"`
	RawResponse     string          `json:"raw_response,omitempty"`
	ScanStatus      string          `json:"scan_status"`
	ScanID          string          `json:"scan_id,omitempty"`
	Progress        model.Progress  `json:"progress"`
	Findings        []model.Finding `json:"findings,omitempty"`
	FindingsCount   int             `json:"findings_count"`
	HighestSeverity string          `json:"highest_severity,omitempty"`
	Error           string          `json:"error,omitempty"`
	ResponsePending bool            `json:"response_pending,omitempty"`
	Scheme          string          `json:"scheme,omitempty"`
	Baseline        model.Response  `json:"-"`
	Cold            bool            `json:"-"`
}

type Session struct {
	mu                sync.RWMutex
	cfg               SessionConfig
	id                string
	status            string
	created           time.Time
	lastErr           string
	scope             map[string]bool
	globalScope       bool
	allowOutOfScope   bool
	revision          uint64
	assetRevision     uint64
	progressRevision  uint64
	findingRevision   uint64
	assets            map[string]*Asset
	order             []string
	observed          int
	tunnels           int
	counters          Counters
	server            *http.Server
	listener          net.Listener
	tunnelConns       map[net.Conn]net.Conn
	interceptions     map[string]*interceptionItem
	interceptOrder    []string
	pendingIntercepts int
	interceptRevision uint64
	interceptChanged  chan struct{}
	transport         *http.Transport
	clientTLS         *tls.Certificate
}

type Manager struct {
	mu          sync.RWMutex
	sessions    map[string]*Session
	closeOnce   sync.Once
	scanner     Scanner
	logger      *slog.Logger
	transport   *http.Transport
	persistence *persistenceStore
	historyMu   sync.RWMutex
	history     *list.List
	historyByID map[string]*list.Element
	changeMu    sync.Mutex
	changeRev   uint64
	changed     chan struct{}
	mitmMu      sync.Mutex
	mitm        *mitmCA
	mitmDir     string
	ephemeralCA bool
}

func New(scanner Scanner, logger *slog.Logger) *Manager {
	return NewPersistent(scanner, logger, "")
}

func NewPersistent(scanner Scanner, logger *slog.Logger, stateDir string) *Manager {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableCompression = true
	manager := &Manager{
		sessions: make(map[string]*Session), scanner: scanner, logger: logger, transport: transport,
		history: list.New(), historyByID: make(map[string]*list.Element), changeRev: 1, changed: make(chan struct{}),
	}
	if strings.TrimSpace(stateDir) != "" {
		manager.mitmDir = filepath.Join(stateDir, "proxy_ca")
		manager.persistence = newPersistenceStore(stateDir, logger, manager)
		manager.restoreSessions()
	}
	manager.rebuildHistoryIndex()
	return manager
}

func historyAssetKey(sessionID, assetID string) string { return sessionID + "\x00" + assetID }

func (m *Manager) notifyChange() {
	m.changeMu.Lock()
	m.changeRev++
	close(m.changed)
	m.changed = make(chan struct{})
	m.changeMu.Unlock()
}

func (m *Manager) WaitChanges(ctx context.Context, since uint64, wait time.Duration) uint64 {
	if wait <= 0 || wait > 30*time.Second {
		wait = 25 * time.Second
	}
	m.changeMu.Lock()
	revision, changed := m.changeRev, m.changed
	m.changeMu.Unlock()
	if since == revision {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
		case <-timer.C:
		case <-changed:
		}
	}
	m.changeMu.Lock()
	revision = m.changeRev
	m.changeMu.Unlock()
	return revision
}

func (m *Manager) indexAsset(sessionID string, asset Asset, recent bool) {
	if sessionID == "" || asset.ID == "" {
		return
	}
	value := HistoricalAsset{Asset: asset.summary(), WebScanID: sessionID}
	key := historyAssetKey(sessionID, asset.ID)
	m.historyMu.Lock()
	if element := m.historyByID[key]; element != nil {
		element.Value = value
		if recent {
			m.history.MoveToFront(element)
		}
	} else {
		m.historyByID[key] = m.history.PushFront(value)
	}
	m.historyMu.Unlock()
}

func (m *Manager) refreshHistoryAsset(sessionID, assetID string, recent bool) {
	session, ok := m.session(sessionID)
	if !ok {
		return
	}
	session.mu.RLock()
	asset := session.assets[assetID]
	if asset == nil {
		session.mu.RUnlock()
		return
	}
	summary := asset.summary()
	session.mu.RUnlock()
	m.indexAsset(sessionID, summary, recent)
}

func (m *Manager) rebuildHistoryIndex() {
	type indexed struct {
		sessionID string
		asset     Asset
	}
	items := make([]indexed, 0)
	m.mu.RLock()
	for _, session := range m.sessions {
		session.mu.RLock()
		for _, fingerprint := range session.order {
			if asset := session.assets[fingerprint]; asset != nil {
				items = append(items, indexed{sessionID: session.id, asset: asset.summary()})
			}
		}
		session.mu.RUnlock()
	}
	m.mu.RUnlock()
	sort.SliceStable(items, func(i, j int) bool { return items[i].asset.LastSeen.After(items[j].asset.LastSeen) })
	m.historyMu.Lock()
	m.history.Init()
	m.historyByID = make(map[string]*list.Element, len(items))
	for _, item := range items {
		value := HistoricalAsset{Asset: item.asset, WebScanID: item.sessionID}
		element := m.history.PushBack(value)
		m.historyByID[historyAssetKey(item.sessionID, item.asset.ID)] = element
	}
	m.historyMu.Unlock()
}

func (m *Manager) removeSessionFromHistory(sessionID string) {
	prefix := sessionID + "\x00"
	m.historyMu.Lock()
	for key, element := range m.historyByID {
		if strings.HasPrefix(key, prefix) {
			m.history.Remove(element)
			delete(m.historyByID, key)
		}
	}
	m.historyMu.Unlock()
}

func (m *Manager) clearHistoryIndex() {
	m.historyMu.Lock()
	m.history.Init()
	m.historyByID = make(map[string]*list.Element)
	m.historyMu.Unlock()
}

func adjustStatusCounter(counters *Counters, status string, delta int) {
	switch strings.ToLower(status) {
	case "queued":
		counters.Queued += delta
	case "scanning", "running":
		counters.Scanning += delta
	case "completed":
		counters.Completed += delta
	case "failed", "cancelled":
		counters.Failed += delta
	}
}

func setAssetStatusLocked(session *Session, asset *Asset, status string) {
	if asset == nil || asset.ScanStatus == status {
		return
	}
	adjustStatusCounter(&session.counters, asset.ScanStatus, -1)
	asset.ScanStatus = status
	adjustStatusCounter(&session.counters, asset.ScanStatus, 1)
}

func (m *Manager) Create(cfg SessionConfig) (SessionView, error) {
	if cfg.ProxyListen == "" {
		cfg.ProxyListen = "127.0.0.1:8088"
	}
	cfg.ScanMode = strings.ToLower(strings.TrimSpace(cfg.ScanMode))
	if cfg.ScanMode == "" {
		cfg.ScanMode = "passive"
	}
	targetValue := strings.TrimSpace(cfg.TargetURL)
	globalScope := targetValue == "" || targetValue == "*"
	if globalScope && cfg.ScanMode != "passive" {
		return SessionView{}, errors.New("全局作用域只允许使用 passive 模式")
	}
	if globalScope && !loopbackListen(cfg.ProxyListen) {
		return SessionView{}, errors.New("全局作用域的代理监听地址必须是本机环回地址")
	}
	var target *url.URL
	if globalScope {
		cfg.TargetURL = "*"
		cfg.ScopeHosts = []string{"*"}
	} else {
		var err error
		target, err = url.Parse(targetValue)
		if err != nil || target.Hostname() == "" || (target.Scheme != "http" && target.Scheme != "https") {
			return SessionView{}, errors.New("target_url 必须是完整的 HTTP/HTTPS URL，或留空/填写 * 使用全局 Passive")
		}
		cfg.TargetURL = target.String()
	}
	if cfg.InterceptTimeout == 0 {
		cfg.InterceptTimeout = 60
	}
	if cfg.InterceptTimeout < 5 || cfg.InterceptTimeout > 300 {
		return SessionView{}, errors.New("intercept_timeout_seconds 必须在 5 到 300 之间")
	}
	cfg.InterceptOnTimeout = strings.ToLower(strings.TrimSpace(cfg.InterceptOnTimeout))
	if cfg.InterceptOnTimeout == "" {
		cfg.InterceptOnTimeout = "drop"
	}
	if cfg.InterceptOnTimeout != "forward" && cfg.InterceptOnTimeout != "drop" {
		return SessionView{}, errors.New("intercept_on_timeout 必须是 forward 或 drop")
	}
	if cfg.MaxPendingIntercepts == 0 {
		cfg.MaxPendingIntercepts = 50
	}
	if cfg.MaxPendingIntercepts < 1 || cfg.MaxPendingIntercepts > 200 {
		return SessionView{}, errors.New("max_pending_intercepts 必须在 1 到 200 之间")
	}
	var extensionErr error
	cfg.StaticExtensions, extensionErr = normalizeStaticExtensions(cfg.StaticExtensions)
	if extensionErr != nil {
		return SessionView{}, extensionErr
	}
	cfg.BrowserOwner = strings.TrimSpace(cfg.BrowserOwner)
	if len(cfg.BrowserOwner) > 128 {
		return SessionView{}, errors.New("browser_owner 长度不能超过 128")
	}
	cfg.ClientTLSFile = strings.TrimSpace(cfg.ClientTLSFile)
	clientTLSPassword := cfg.ClientTLSPassword
	cfg.ClientTLSPassword = ""
	if cfg.ClientTLSFile != "" && !cfg.InterceptTLS {
		return SessionView{}, errors.New("选择客户端 TLS 证书时必须启用 HTTPS 解密")
	}
	var clientIdentity *tls.Certificate
	if cfg.ClientTLSFile != "" {
		var parseErr error
		clientIdentity, parseErr = clientcert.Parse(&model.ClientTLSInput{
			File: cfg.ClientTLSFile, Password: clientTLSPassword,
		})
		if parseErr != nil {
			return SessionView{}, parseErr
		}
	}
	if cfg.InterceptTLS {
		if _, err := m.ensureMITMCA(); err != nil {
			return SessionView{}, fmt.Errorf("初始化 HTTPS 解密 CA 失败: %w", err)
		}
	}
	scope := make(map[string]bool)
	if !globalScope {
		scope[strings.ToLower(target.Hostname())] = true
		for _, value := range cfg.ScopeHosts {
			host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
			if strings.Contains(host, ":") {
				if parsed, _, splitErr := net.SplitHostPort(host); splitErr == nil {
					host = parsed
				}
			}
			if host == "" || net.ParseIP(host) == nil && strings.ContainsAny(host, "/\\ \r\n") {
				return SessionView{}, fmt.Errorf("scope_hosts 包含无效主机 %q", value)
			}
			scope[host] = true
		}
		cfg.ScopeHosts = sortedKeys(scope)
	}
	listener, err := net.Listen("tcp4", cfg.ProxyListen)
	if err != nil {
		return SessionView{}, fmt.Errorf("代理端口监听失败: %w", err)
	}
	session := &Session{
		id: newID("web"), cfg: cfg, status: "listening", created: time.Now().UTC(), scope: scope, globalScope: globalScope,
		allowOutOfScope: loopbackListen(cfg.ProxyListen), revision: 1, assetRevision: 1, progressRevision: 1, findingRevision: 1,
		assets: make(map[string]*Asset), listener: listener, tunnelConns: make(map[net.Conn]net.Conn),
		interceptions: make(map[string]*interceptionItem), interceptRevision: 1, interceptChanged: make(chan struct{}),
		clientTLS: clientIdentity,
	}
	session.transport = m.transport.Clone()
	session.transport.Proxy = nil
	session.transport.DisableCompression = true
	if clientIdentity != nil {
		tlsConfig := session.transport.TLSClientConfig
		if tlsConfig == nil {
			tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		} else {
			tlsConfig = tlsConfig.Clone()
		}
		tlsConfig.Certificates = []tls.Certificate{*clientIdentity}
		session.transport.TLSClientConfig = tlsConfig
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { m.proxy(session, w, r) }), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second}
	session.server = server
	m.mu.Lock()
	m.sessions[session.id] = session
	m.mu.Unlock()
	m.markSessionDirty(session.id)
	go func() {
		if serveErr := server.Serve(listener); serveErr != nil && serveErr != http.ErrServerClosed {
			session.mu.Lock()
			session.status, session.lastErr = "failed", serveErr.Error()
			session.mu.Unlock()
		}
	}()
	m.logger.Info("WEB scan proxy started", "session_id", session.id, "listen", listener.Addr().String(), "scope", cfg.ScopeHosts)
	return session.view(false), nil
}

func normalizeStaticExtensions(values []string) ([]string, error) {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		extension := strings.ToLower(strings.TrimSpace(value))
		if extension == "" {
			continue
		}
		if !strings.HasPrefix(extension, ".") {
			extension = "." + extension
		}
		if len(extension) < 2 || len(extension) > 24 || strings.ContainsAny(extension[1:], ". /\\\r\n\t") {
			return nil, fmt.Errorf("静态资源后缀 %q 无效", value)
		}
		for _, char := range extension[1:] {
			if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9')) {
				return nil, fmt.Errorf("静态资源后缀 %q 只能包含字母和数字", value)
			}
		}
		if !seen[extension] {
			seen[extension] = true
			result = append(result, extension)
		}
	}
	sort.Strings(result)
	return result, nil
}

func loopbackListen(address string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return false
	}
	host = strings.Trim(host, "[]")
	return strings.EqualFold(host, "localhost") || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
}

func (m *Manager) List() []SessionView {
	m.mu.RLock()
	items := make([]*Session, 0, len(m.sessions))
	for _, session := range m.sessions {
		items = append(items, session)
	}
	m.mu.RUnlock()
	result := make([]SessionView, 0, len(items))
	for _, session := range items {
		result = append(result, session.view(false))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.After(result[j].CreatedAt) })
	return result
}

func (m *Manager) Get(id string) (SessionView, bool) {
	session, ok := m.session(id)
	if !ok {
		return SessionView{}, false
	}
	return session.view(true), true
}

func (m *Manager) Summary(id string) (SessionView, bool) {
	session, ok := m.session(id)
	if !ok {
		return SessionView{}, false
	}
	return session.view(false), true
}

func (m *Manager) FindingSummaries(id string) ([]SiteFinding, bool) {
	session, ok := m.session(id)
	if !ok {
		return nil, false
	}
	session.mu.RLock()
	result := make([]SiteFinding, 0)
	for _, key := range session.order {
		asset := session.assets[key]
		if asset == nil {
			continue
		}
		for _, finding := range asset.Findings {
			summary := finding
			summary.Evidence = nil
			result = append(result, SiteFinding{
				Finding: summary, AssetID: asset.ID, InterfaceMethod: asset.Method,
				InterfaceHost: asset.Host, InterfacePath: asset.NormalizedPath,
			})
		}
	}
	session.mu.RUnlock()
	return result, true
}

// HistoricalFindingSummaries returns lightweight findings from every retained
// WEB scan task. The session identifier lets the UI open the correct cold
// asset without loading request/response bodies for the whole report.
func (m *Manager) HistoricalFindingSummaries() []SiteFinding {
	m.mu.RLock()
	sessions := make([]*Session, 0, len(m.sessions))
	for _, session := range m.sessions {
		sessions = append(sessions, session)
	}
	m.mu.RUnlock()
	result := make([]SiteFinding, 0)
	for _, session := range sessions {
		session.mu.RLock()
		for _, key := range session.order {
			asset := session.assets[key]
			if asset == nil {
				continue
			}
			for _, finding := range asset.Findings {
				summary := finding
				summary.Evidence = nil
				result = append(result, SiteFinding{
					Finding: summary, WebScanID: session.id, AssetID: asset.ID,
					InterfaceMethod: asset.Method, InterfaceHost: asset.Host,
					InterfacePath: asset.NormalizedPath,
				})
			}
		}
		session.mu.RUnlock()
	}
	return result
}

// HistoricalFindingReport returns compact groups by default. The affected
// interface summaries are materialized only after the operator opens a group,
// keeping the normal asset-page payload bounded as findings accumulate.
func (m *Manager) HistoricalFindingReport(group string) ([]FindingGroup, []SiteFinding) {
	type aggregate struct {
		group      FindingGroup
		interfaces map[string]struct{}
	}
	groups := make(map[string]*aggregate)
	selected := make([]SiteFinding, 0)
	m.mu.RLock()
	sessions := make([]*Session, 0, len(m.sessions))
	for _, session := range m.sessions {
		sessions = append(sessions, session)
	}
	m.mu.RUnlock()
	for _, session := range sessions {
		session.mu.RLock()
		for _, key := range session.order {
			asset := session.assets[key]
			if asset == nil {
				continue
			}
			for _, finding := range asset.Findings {
				groupKey := finding.PluginID + "\x1f" + finding.Title
				entry := groups[groupKey]
				if entry == nil {
					entry = &aggregate{group: FindingGroup{Key: groupKey, PluginID: finding.PluginID, Title: finding.Title}, interfaces: make(map[string]struct{})}
					groups[groupKey] = entry
				}
				entry.group.Count++
				entry.interfaces[session.id+"\x00"+asset.ID] = struct{}{}
				if group == groupKey {
					summary := finding
					summary.Evidence = nil
					selected = append(selected, SiteFinding{Finding: summary, WebScanID: session.id, AssetID: asset.ID, InterfaceMethod: asset.Method, InterfaceHost: asset.Host, InterfacePath: asset.NormalizedPath})
				}
			}
		}
		session.mu.RUnlock()
	}
	result := make([]FindingGroup, 0, len(groups))
	for _, entry := range groups {
		entry.group.Interfaces = len(entry.interfaces)
		result = append(result, entry.group)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Count == result[j].Count {
			return result[i].Title < result[j].Title
		}
		return result[i].Count > result[j].Count
	})
	return result, selected
}

func (m *Manager) Assets(id string) ([]Asset, bool) {
	session, ok := m.session(id)
	if !ok {
		return nil, false
	}
	session.mu.RLock()
	result := make([]Asset, 0, len(session.order))
	for i := len(session.order) - 1; i >= 0; i-- {
		if asset := session.assets[session.order[i]]; asset != nil {
			result = append(result, asset.summary())
		}
	}
	session.mu.RUnlock()
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].LastSeen.Equal(result[j].LastSeen) {
			return result[i].FirstSeen.After(result[j].FirstSeen)
		}
		return result[i].LastSeen.After(result[j].LastSeen)
	})
	return result, true
}

func (m *Manager) AssetsPage(id, query, status string, page, pageSize int) ([]Asset, int, bool) {
	session, ok := m.session(id)
	if !ok {
		return nil, 0, false
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 50
	}
	if pageSize > 100 {
		pageSize = 100
	}
	query = strings.ToLower(strings.TrimSpace(query))
	status = strings.ToLower(strings.TrimSpace(status))
	session.mu.RLock()
	filtered := make([]Asset, 0, len(session.order))
	for i := len(session.order) - 1; i >= 0; i-- {
		asset := session.assets[session.order[i]]
		if asset == nil {
			continue
		}
		haystack := strings.ToLower(asset.Method + " " + asset.Host + " " + asset.NormalizedPath)
		if query != "" && !strings.Contains(haystack, query) {
			continue
		}
		if status != "" && strings.ToLower(asset.ScanStatus) != status {
			continue
		}
		filtered = append(filtered, asset.summary())
	}
	session.mu.RUnlock()
	sort.SliceStable(filtered, func(i, j int) bool {
		if filtered[i].LastSeen.Equal(filtered[j].LastSeen) {
			return filtered[i].FirstSeen.After(filtered[j].FirstSeen)
		}
		return filtered[i].LastSeen.After(filtered[j].LastSeen)
	})
	total := len(filtered)
	start := (page - 1) * pageSize
	if start >= total {
		return []Asset{}, total, true
	}
	end := min(start+pageSize, total)
	return filtered[start:end], total, true
}

// HistoricalAssetsPage provides one server-side paginated view over all
// retained tasks. Asset bodies and findings remain cold and are only loaded
// when the user opens one row.
func (m *Manager) HistoricalAssetsPage(query, status string, page, pageSize int) ([]HistoricalAsset, int) {
	// Restored and proxy-created assets are indexed incrementally. This fallback
	// also keeps direct in-process Session mutations (tests/integrations) correct
	// without putting an O(N log N) sort on the normal first-page hot path.
	m.historyMu.RLock()
	historyEmpty := m.history.Len() == 0
	m.historyMu.RUnlock()
	if historyEmpty {
		m.rebuildHistoryIndex()
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 50
	}
	if pageSize > 100 {
		pageSize = 100
	}
	query = strings.ToLower(strings.TrimSpace(query))
	status = strings.ToLower(strings.TrimSpace(status))
	start := (page - 1) * pageSize
	result := make([]HistoricalAsset, 0, pageSize)
	total := 0
	m.historyMu.RLock()
	if query == "" && status == "" {
		total = m.history.Len()
		index := 0
		for element := m.history.Front(); element != nil && len(result) < pageSize; element = element.Next() {
			if index >= start {
				result = append(result, element.Value.(HistoricalAsset))
			}
			index++
		}
		m.historyMu.RUnlock()
		return result, total
	}
	for element := m.history.Front(); element != nil; element = element.Next() {
		item := element.Value.(HistoricalAsset)
		haystack := strings.ToLower(item.Method + " " + item.Host + " " + item.NormalizedPath)
		if query != "" && !strings.Contains(haystack, query) {
			continue
		}
		if status != "" && strings.ToLower(item.ScanStatus) != status {
			continue
		}
		if total >= start && len(result) < pageSize {
			result = append(result, item)
		}
		total++
	}
	m.historyMu.RUnlock()
	return result, total
}

func (m *Manager) Asset(sessionID, assetID string) (Asset, bool) {
	session, ok := m.session(sessionID)
	if !ok {
		return Asset{}, false
	}
	session.mu.RLock()
	asset, exists := session.assets[assetID]
	if !exists {
		session.mu.RUnlock()
		return Asset{}, false
	}
	result := asset.clone()
	cold := asset.Cold
	session.mu.RUnlock()
	if cold && m.persistence != nil {
		if persisted, err := m.persistence.readAsset(sessionID, assetID); err == nil {
			persisted.Progress = result.Progress
			persisted.ScanStatus = result.ScanStatus
			persisted.ScanID = result.ScanID
			persisted.Error = result.Error
			persisted.SeenCount = result.SeenCount
			persisted.LastSeen = result.LastSeen
			persisted.FindingsCount = result.FindingsCount
			persisted.HighestSeverity = result.HighestSeverity
			result = persisted
		}
	}
	return result, true
}

func (m *Manager) Scan(sessionID, assetID string) error {
	session, ok := m.session(sessionID)
	if !ok {
		return errors.New("WEB扫描任务不存在")
	}
	if err := m.warmAsset(session, assetID); err != nil {
		return err
	}
	session.mu.Lock()
	asset := session.assets[assetID]
	if asset == nil {
		session.mu.Unlock()
		return errors.New("接口资产不存在")
	}
	if asset.ScanStatus == "queued" || asset.ScanStatus == "scanning" {
		session.mu.Unlock()
		return errors.New("该接口正在扫描")
	}
	setAssetStatusLocked(session, asset, "queued")
	asset.Error = ""
	session.revision++
	session.progressRevision++
	session.mu.Unlock()
	m.markAssetDirty(sessionID, assetID)
	m.refreshHistoryAsset(sessionID, assetID, false)
	m.notifyChange()
	go m.submit(session, assetID)
	return nil
}

func (m *Manager) Delete(id string) bool {
	m.mu.Lock()
	session, ok := m.sessions[id]
	if ok {
		delete(m.sessions, id)
	}
	m.mu.Unlock()
	if !ok {
		return false
	}
	session.mu.Lock()
	var scanIDs []string
	for _, asset := range session.assets {
		if asset.ScanID != "" && (asset.ScanStatus == "queued" || asset.ScanStatus == "scanning") {
			scanIDs = append(scanIDs, asset.ScanID)
		}
	}
	session.mu.Unlock()
	for _, scanID := range scanIDs {
		m.scanner.Cancel(scanID)
	}
	m.shutdownProxy(session)
	if session.transport != nil {
		session.transport.CloseIdleConnections()
	}
	m.removeSessionFromHistory(id)
	m.removePersisted(id)
	m.notifyChange()
	return true
}

// ClearHistoricalAssets removes captured interfaces and findings from every
// retained task while leaving proxy listeners and task configuration intact.
// It is intentionally separate from Delete so clearing history cannot
// accidentally stop an active proxy.
func (m *Manager) ClearHistoricalAssets() int {
	m.mu.RLock()
	sessions := make([]*Session, 0, len(m.sessions))
	for _, session := range m.sessions {
		sessions = append(sessions, session)
	}
	m.mu.RUnlock()
	removed := 0
	var scanIDs []string
	for _, session := range sessions {
		session.mu.Lock()
		removed += len(session.order)
		for _, fingerprint := range session.order {
			if asset := session.assets[fingerprint]; asset != nil && asset.ScanID != "" &&
				(asset.ScanStatus == "queued" || asset.ScanStatus == "scanning") {
				scanIDs = append(scanIDs, asset.ScanID)
			}
		}
		session.assets = make(map[string]*Asset)
		session.order = nil
		session.observed = 0
		session.counters = Counters{HTTPSTunnels: session.tunnels}
		session.revision++
		session.assetRevision++
		session.progressRevision++
		session.findingRevision++
		session.mu.Unlock()
		if m.persistence != nil {
			m.persistence.clearAssets(session.id)
		}
		m.markSessionDirty(session.id)
	}
	m.clearHistoryIndex()
	for _, scanID := range scanIDs {
		m.scanner.Cancel(scanID)
	}
	m.notifyChange()
	return removed
}

// StopProxy only closes the browser-facing listener and active CONNECT
// tunnels. Scans already submitted to the engine and all captured assets stay
// alive in memory so the UI can continue showing progress and results.
func (m *Manager) StopProxy(id string) bool {
	session, ok := m.session(id)
	if !ok {
		return false
	}
	m.shutdownProxy(session)
	m.markSessionDirty(id)
	m.notifyChange()
	return true
}

func (m *Manager) shutdownProxy(session *Session) {
	session.mu.Lock()
	if session.status == "stopped" {
		session.mu.Unlock()
		return
	}
	session.status = "stopped"
	session.revision++
	for client, target := range session.tunnelConns {
		_ = client.Close()
		_ = target.Close()
	}
	session.tunnelConns = make(map[net.Conn]net.Conn)
	session.mu.Unlock()
	session.releasePendingInterceptions("代理已关闭")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if session.server != nil {
		_ = session.server.Shutdown(ctx)
	}
}

// Browser lifecycle notifications are retained as compatibility no-ops.
// A browser refresh, suspended tab or missed heartbeat must never own the
// lifetime of a proxy task or its captured evidence.
func (m *Manager) TouchBrowserOwner(string)      {}
func (m *Manager) ScheduleBrowserCleanup(string) {}

func (m *Manager) Close() {
	m.closeOnce.Do(func() {
		m.mu.RLock()
		sessions := make([]*Session, 0, len(m.sessions))
		for _, session := range m.sessions {
			sessions = append(sessions, session)
		}
		m.mu.RUnlock()
		for _, session := range sessions {
			m.shutdownProxy(session)
			if session.transport != nil {
				session.transport.CloseIdleConnections()
			}
		}
		if m.persistence != nil {
			m.persistence.flushAll(m)
			m.persistence.close()
		}
		m.transport.CloseIdleConnections()
		if m.ephemeralCA && m.mitmDir != "" {
			_ = os.RemoveAll(m.mitmDir)
		}
	})
}

func (m *Manager) session(id string) (*Session, bool) {
	m.mu.RLock()
	session, ok := m.sessions[id]
	m.mu.RUnlock()
	return session, ok
}

func (m *Manager) proxy(session *Session, w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		m.connect(session, w, r)
		return
	}
	host := strings.ToLower(r.URL.Hostname())
	if host == "" {
		host = hostname(r.Host)
	}
	if !session.inScope(host) {
		if !session.allowOutOfScope {
			http.Error(w, "HappyScan: target host is outside this WEB scan scope", http.StatusForbidden)
			return
		}
		m.forwardOutOfScope(w, r)
		return
	}
	transactionID := newID("tx")
	target := cloneURL(r.URL)
	if target.Scheme == "" {
		target.Scheme = "http"
	}
	if target.Host == "" {
		target.Host = r.Host
	}
	requestPrefix, requestLarge, err := readBounded(r.Body, maxInterceptBytes)
	if err != nil {
		http.Error(w, "HappyScan proxy: 读取请求失败", http.StatusBadRequest)
		return
	}
	var requestBody io.Reader = bytes.NewReader(requestPrefix)
	if requestLarge {
		requestBody = io.MultiReader(bytes.NewReader(requestPrefix), r.Body)
	}
	requestCapture := &limitedBuffer{limit: maxRequestBytes}
	out := r.Clone(r.Context())
	out.URL, out.RequestURI, out.Host = target, "", r.Host
	out.Body = io.NopCloser(io.TeeReader(requestBody, requestCapture))
	out.ContentLength = r.ContentLength
	stripHop(out.Header)
	if !requestLarge {
		raw := rawRequest(r, requestPrefix)
		decision, intercepted := session.awaitInterception(
			r.Context(), "request", transactionID, raw, r.Method, hostname(r.Host),
			r.URL.RequestURI(), r.Header.Get("Content-Type"), int64(len(requestPrefix)), requestEditable(r.Header.Get("Content-Type")),
		)
		if intercepted && decision.action == "drop" {
			writeProxyDrop(w, "请求已由 HappyScan 丢弃")
			return
		}
		if intercepted && decision.raw != "" && decision.raw != raw {
			parsed, parseErr := httpraw.ParseWithLimit(decision.raw, target.Scheme, maxInterceptBytes)
			if parseErr != nil {
				http.Error(w, "HappyScan 修改请求无效: "+parseErr.Error(), http.StatusBadRequest)
				return
			}
			if !session.inScope(parsed.Host()) {
				http.Error(w, "HappyScan: 修改后的 Host 超出本次作用域", http.StatusForbidden)
				return
			}
			requestURL, urlErr := parsed.URL()
			if urlErr != nil {
				http.Error(w, "HappyScan 修改请求 URL 无效", http.StatusBadRequest)
				return
			}
			parsedURL, urlErr := url.Parse(requestURL)
			if urlErr != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
				http.Error(w, "HappyScan 仅允许修改后转发 HTTP/HTTPS 请求", http.StatusBadRequest)
				return
			}
			target = parsedURL
			out = r.Clone(r.Context())
			out.Method, out.URL, out.RequestURI, out.Host = parsed.Method, parsedURL, "", parsed.Authority()
			out.Header = parsed.TransportHeaders()
			out.Body = io.NopCloser(bytes.NewReader(parsed.Body))
			out.ContentLength = int64(len(parsed.Body))
			requestCapture = &limitedBuffer{limit: maxRequestBytes}
			out.Body = io.NopCloser(io.TeeReader(out.Body, requestCapture))
		}
	}
	started := time.Now()
	response, err := session.roundTripper(m.transport).RoundTrip(out)
	if err != nil {
		http.Error(w, "HappyScan proxy: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	session.mu.RLock()
	interceptResponses := session.cfg.InterceptResponses
	filterStatic := session.cfg.FilterStatic
	autoScan := session.cfg.AutoScan
	session.mu.RUnlock()
	var assetID string
	var created, provisional bool
	var rawReq string
	if !requestCapture.truncated && !interceptResponses && !(filterStatic && session.staticResource(r.URL.Path)) {
		rawReq = rawRequest(out, requestCapture.Bytes())
		assetID, created = session.beginRecord(out, rawReq)
		provisional = assetID != ""
		if provisional {
			m.refreshHistoryAsset(session.id, assetID, true)
			m.markAssetDirty(session.id, assetID)
			m.notifyChange()
		}
	}
	responseLimit := maxResponseBytes
	if interceptResponses {
		responseLimit = maxInterceptBytes
	}
	responsePrefix, responseLarge, readErr := readBounded(response.Body, responseLimit)
	if readErr != nil {
		if provisional {
			session.finalizeRecord(assetID, rawReq, "", model.Response{}, "读取响应失败: "+readErr.Error())
			m.refreshHistoryAsset(session.id, assetID, false)
			m.markAssetDirty(session.id, assetID)
			m.notifyChange()
		}
		http.Error(w, "HappyScan proxy: 读取响应失败", http.StatusBadGateway)
		return
	}
	baselineBody, baselineHeader, baselineCharset, baselineTruncated := capturedResponse(response, responsePrefix, responseLarge)
	finalStatus := response.StatusCode
	finalHeader := response.Header.Clone()
	var responseBody io.Reader = bytes.NewReader(responsePrefix)
	if responseLarge {
		responseBody = io.MultiReader(bytes.NewReader(responsePrefix), response.Body)
	}
	if !responseLarge && !streamingResponse(response) {
		raw := rawResponseParts(response.Status, baselineHeader, baselineBody, baselineTruncated)
		decision, intercepted := session.awaitInterception(
			r.Context(), "response", transactionID, raw, out.Method, hostname(out.Host),
			out.URL.RequestURI(), response.Header.Get("Content-Type"), int64(len(responsePrefix)), responseEditable(response.Header),
		)
		if intercepted && decision.action == "drop" {
			writeProxyDrop(w, "响应已由 HappyScan 丢弃")
			return
		}
		if intercepted && decision.raw != "" && decision.raw != raw {
			status, header, body, parseErr := parseEditedResponse(decision.raw)
			if parseErr != nil {
				http.Error(w, "HappyScan 修改响应无效: "+parseErr.Error(), http.StatusBadGateway)
				return
			}
			finalStatus, finalHeader, responseBody = status, header, bytes.NewReader(body)
		}
	}
	if requestCapture.truncated {
		copyHeaders(w.Header(), finalHeader)
		stripHop(w.Header())
		w.Header().Del("Content-Length")
		w.WriteHeader(finalStatus)
		_, _ = io.Copy(w, responseBody)
		return
	}
	body := requestCapture.Bytes()
	rawReq = rawRequest(out, body)
	rawResp := rawResponseParts(response.Status, baselineHeader, baselineBody, baselineTruncated)
	if filterStatic && session.staticResource(r.URL.Path) {
		copyHeaders(w.Header(), finalHeader)
		stripHop(w.Header())
		w.Header().Del("Content-Length")
		w.WriteHeader(finalStatus)
		_, _ = io.Copy(w, responseBody)
		return
	}
	headers, headerValues := responseHeaders(baselineHeader)
	baseline := model.Response{
		StatusCode: response.StatusCode, Headers: headers, HeaderValues: headerValues,
		Body: append([]byte(nil), baselineBody...), Elapsed: time.Since(started), URL: target.String(),
		Charset: baselineCharset, RawBytes: capturedWireBytes(response, responsePrefix), Truncated: baselineTruncated,
	}
	if provisional {
		session.finalizeRecord(assetID, rawReq, rawResp, baseline, "")
	} else {
		assetID, created = session.record(out, rawReq, rawResp, baseline)
	}
	if assetID != "" {
		m.refreshHistoryAsset(session.id, assetID, true)
		m.markAssetDirty(session.id, assetID)
		m.notifyChange()
	}
	copyHeaders(w.Header(), finalHeader)
	stripHop(w.Header())
	w.Header().Del("Content-Length")
	w.WriteHeader(finalStatus)
	_, _ = io.Copy(w, responseBody)
	if created && autoScan {
		go m.submit(session, assetID)
	}
}

func (s *Session) staticResource(requestPath string) bool {
	extension := strings.ToLower(path.Ext(requestPath))
	if staticExt[extension] {
		return true
	}
	for _, configured := range s.cfg.StaticExtensions {
		if extension == configured {
			return true
		}
	}
	return false
}

// forwardOutOfScope keeps normal browsing functional when the proxy listens
// only on loopback. It deliberately bypasses buffering, interception, asset
// creation and scanning so unrelated browser traffic never enters test data.
func (m *Manager) forwardOutOfScope(w http.ResponseWriter, r *http.Request) {
	target := cloneURL(r.URL)
	if target.Scheme == "" {
		target.Scheme = "http"
	}
	if target.Scheme != "http" {
		http.Error(w, "HappyScan: non-CONNECT HTTPS proxy request is unsupported", http.StatusBadRequest)
		return
	}
	if target.Host == "" {
		target.Host = r.Host
	}
	out := r.Clone(r.Context())
	out.URL, out.RequestURI, out.Host = target, "", r.Host
	stripHop(out.Header)
	response, err := m.transport.RoundTrip(out)
	if err != nil {
		http.Error(w, "HappyScan proxy: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	copyHeaders(w.Header(), response.Header)
	stripHop(w.Header())
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

func (m *Manager) connect(session *Session, w http.ResponseWriter, r *http.Request) {
	host := hostname(r.Host)
	inScope := session.inScope(host)
	if !inScope && !session.allowOutOfScope {
		http.Error(w, "HappyScan: CONNECT host is outside this WEB scan scope", http.StatusForbidden)
		return
	}
	session.mu.RLock()
	interceptTLS := session.cfg.InterceptTLS
	session.mu.RUnlock()
	if inScope && interceptTLS {
		m.connectMITM(session, w, r)
		return
	}
	target, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, "HappyScan CONNECT failed", http.StatusBadGateway)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		target.Close()
		http.Error(w, "HappyScan CONNECT is unavailable", http.StatusInternalServerError)
		return
	}
	client, _, err := hijacker.Hijack()
	if err != nil {
		target.Close()
		return
	}
	session.mu.Lock()
	if len(session.tunnelConns) >= 256 {
		session.mu.Unlock()
		_ = client.Close()
		_ = target.Close()
		return
	}
	if inScope {
		session.tunnels++
		session.counters.HTTPSTunnels++
		session.revision++
	}
	session.tunnelConns[client] = target
	session.mu.Unlock()
	if inScope {
		m.markSessionDirty(session.id)
		m.notifyChange()
	}
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\nProxy-Agent: HappyScan-V3\r\n\r\n"))
	go tunnelPair(session, client, target)
}

func (m *Manager) submit(session *Session, assetID string) {
	defer m.markAssetDirty(session.id, assetID)
	session.mu.Lock()
	asset := session.assets[assetID]
	if asset == nil {
		session.mu.Unlock()
		return
	}
	setAssetStatusLocked(session, asset, "queued")
	session.revision++
	session.progressRevision++
	scheme := asset.Scheme
	if scheme == "" {
		scheme = "http"
	}
	input := model.ScanInput{HTTP: asset.RawRequest, ScanType: append([]string(nil), session.cfg.Plugins...), Mode: session.cfg.ScanMode, Scheme: scheme}
	baseline := asset.Baseline
	session.mu.Unlock()
	m.refreshHistoryAsset(session.id, assetID, false)
	m.notifyChange()
	scanID, err := m.scanner.Start(input, baseline)
	session.mu.Lock()
	asset = session.assets[assetID]
	if asset == nil {
		session.mu.Unlock()
		return
	}
	if err != nil {
		setAssetStatusLocked(session, asset, "failed")
		asset.Error = err.Error()
		session.revision++
		session.progressRevision++
		session.mu.Unlock()
		m.refreshHistoryAsset(session.id, assetID, false)
		m.notifyChange()
		return
	}
	asset.ScanID = scanID
	setAssetStatusLocked(session, asset, "queued")
	session.revision++
	session.progressRevision++
	session.mu.Unlock()
	m.refreshHistoryAsset(session.id, assetID, false)
	m.notifyChange()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		view, findings, ok := m.scanner.Snapshot(scanID)
		if !ok {
			session.mu.Lock()
			if current := session.assets[assetID]; current != nil {
				setAssetStatusLocked(session, current, "failed")
				current.Error = "扫描任务已过期"
				session.revision++
				session.progressRevision++
			}
			session.mu.Unlock()
			m.refreshHistoryAsset(session.id, assetID, false)
			m.notifyChange()
			return
		}
		session.mu.Lock()
		current := session.assets[assetID]
		if current == nil {
			session.mu.Unlock()
			return
		}
		oldStatus, oldError, oldProgress := current.ScanStatus, current.Error, current.Progress
		current.Progress = view.Progress
		nextStatus := view.Status
		if nextStatus == "running" {
			nextStatus = "scanning"
		}
		setAssetStatusLocked(session, current, nextStatus)
		current.Error = view.Error
		changed := current.ScanStatus != oldStatus || !progressEqual(current.Progress, oldProgress) || current.Error != oldError
		if changed {
			session.revision++
			session.progressRevision++
		}
		if terminal(view.Status) {
			oldCount, oldSeverity := current.FindingsCount, current.HighestSeverity
			current.Findings = append([]model.Finding(nil), findings...)
			current.FindingsCount = len(findings)
			current.HighestSeverity = highestSeverity(findings)
			session.counters.Findings += current.FindingsCount - oldCount
			if current.FindingsCount != oldCount || current.HighestSeverity != oldSeverity {
				session.revision++
				session.findingRevision++
				changed = true
			}
			session.mu.Unlock()
			m.refreshHistoryAsset(session.id, assetID, false)
			if changed {
				m.notifyChange()
			}
			return
		}
		session.mu.Unlock()
		if changed {
			m.refreshHistoryAsset(session.id, assetID, false)
			m.notifyChange()
		}
	}
}

func (s *Session) record(r *http.Request, request, response string, baseline model.Response) (string, bool) {
	fingerprint, normalized := fingerprintRequest(r, []byte(bodyPart(request)))
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.observed++
	s.counters.ObservedRequests++
	s.revision++
	s.assetRevision++
	if existing := s.assets[fingerprint]; existing != nil {
		existing.SeenCount++
		existing.LastSeen, existing.ResponseStatus = now, baseline.StatusCode
		existing.ResponseBytes = baseline.RawBytes
		existing.RawRequest, existing.RawResponse = request, response
		existing.Baseline = baseline
		existing.Cold = false
		return existing.ID, false
	}
	if len(s.order) >= maxAssets && !s.evictOne() {
		return "", false
	}
	asset := &Asset{ID: newID("asset"), Fingerprint: fingerprint, Method: r.Method, Host: hostname(r.Host), Path: r.URL.EscapedPath(), NormalizedPath: normalized, ContentType: r.Header.Get("Content-Type"), SeenCount: 1, FirstSeen: now, LastSeen: now, ResponseStatus: baseline.StatusCode, ResponseBytes: baseline.RawBytes, RawRequest: request, RawResponse: response, ScanStatus: "observed", Scheme: requestScheme(r), Baseline: baseline}
	s.assets[fingerprint] = asset
	s.assets[asset.ID] = asset
	s.order = append(s.order, fingerprint)
	s.counters.Assets++
	return asset.ID, true
}

func (s *Session) beginRecord(r *http.Request, request string) (string, bool) {
	fingerprint, normalized := fingerprintRequest(r, []byte(bodyPart(request)))
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.observed++
	s.counters.ObservedRequests++
	s.revision++
	s.assetRevision++
	if existing := s.assets[fingerprint]; existing != nil {
		existing.SeenCount++
		existing.LastSeen = now
		existing.RawRequest = request
		existing.ResponsePending = true
		existing.Cold = false
		return existing.ID, false
	}
	if len(s.order) >= maxAssets && !s.evictOne() {
		return "", false
	}
	asset := &Asset{
		ID: newID("asset"), Fingerprint: fingerprint, Method: r.Method, Host: hostname(r.Host),
		Path: r.URL.EscapedPath(), NormalizedPath: normalized, ContentType: r.Header.Get("Content-Type"),
		SeenCount: 1, FirstSeen: now, LastSeen: now, RawRequest: request,
		ScanStatus: "observed", ResponsePending: true, Scheme: requestScheme(r),
	}
	s.assets[fingerprint], s.assets[asset.ID] = asset, asset
	s.order = append(s.order, fingerprint)
	s.counters.Assets++
	return asset.ID, true
}

func (s *Session) finalizeRecord(assetID, request, response string, baseline model.Response, captureErr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	asset := s.assets[assetID]
	if asset == nil {
		return
	}
	asset.ResponsePending = false
	asset.RawRequest = request
	if captureErr != "" {
		asset.Error = captureErr
	} else {
		asset.ResponseStatus = baseline.StatusCode
		asset.ResponseBytes = baseline.RawBytes
		asset.RawResponse = response
		asset.Baseline = baseline
		asset.Error = ""
	}
	asset.Cold = false
	s.revision++
	s.assetRevision++
}

func progressEqual(left, right model.Progress) bool {
	return left.PlannedRequests == right.PlannedRequests &&
		left.ResolvedRequests == right.ResolvedRequests &&
		left.RequestsSent == right.RequestsSent &&
		left.CompletedChecks == right.CompletedChecks &&
		left.TotalChecks == right.TotalChecks
}

func (s *Session) evictOne() bool {
	for index, key := range s.order {
		asset := s.assets[key]
		if asset != nil && asset.ScanStatus != "queued" && asset.ScanStatus != "scanning" {
			delete(s.assets, key)
			delete(s.assets, asset.ID)
			s.order = append(s.order[:index], s.order[index+1:]...)
			return true
		}
	}
	return false
}

func (s *Session) inScope(host string) bool {
	s.mu.RLock()
	ok := s.globalScope && strings.TrimSpace(host) != ""
	if !ok {
		ok = s.scope[strings.ToLower(strings.TrimSuffix(host, "."))]
	}
	s.mu.RUnlock()
	return ok
}

func (s *Session) view(withFindings bool) SessionView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	proxyListen := s.cfg.ProxyListen
	if s.listener != nil {
		proxyListen = s.listener.Addr().String()
	}
	outOfScopePolicy := "reject"
	if s.allowOutOfScope {
		outOfScopePolicy = "pass"
	}
	view := SessionView{ID: s.id, Name: s.cfg.Name, TargetURL: s.cfg.TargetURL, ScopeHosts: append([]string(nil), s.cfg.ScopeHosts...), GlobalScope: s.globalScope, OutOfScopePolicy: outOfScopePolicy, ProxyListen: proxyListen, ScanMode: s.cfg.ScanMode, Plugins: append([]string(nil), s.cfg.Plugins...), AutoScan: s.cfg.AutoScan, FilterStatic: s.cfg.FilterStatic, StaticExtensions: append([]string(nil), s.cfg.StaticExtensions...), BrowserOwner: s.cfg.BrowserOwner, InterceptRequests: s.cfg.InterceptRequests, InterceptResponses: s.cfg.InterceptResponses, InterceptTimeout: s.cfg.InterceptTimeout, InterceptOnTimeout: s.cfg.InterceptOnTimeout, MaxPendingIntercepts: s.cfg.MaxPendingIntercepts, InterceptTLS: s.cfg.InterceptTLS, ClientTLSFile: s.cfg.ClientTLSFile, Status: s.status, CreatedAt: s.created, Revision: s.revision, AssetRevision: s.assetRevision, ProgressRevision: s.progressRevision, FindingRevision: s.findingRevision, InterceptionRevision: s.interceptRevision, LastError: s.lastErr, Counters: s.counters}
	if withFindings {
		for _, key := range s.order {
			asset := s.assets[key]
			if asset == nil {
				continue
			}
			for _, finding := range asset.Findings {
				view.Findings = append(view.Findings, SiteFinding{
					Finding: finding, AssetID: asset.ID, InterfaceMethod: asset.Method,
					InterfaceHost: asset.Host, InterfacePath: asset.NormalizedPath,
				})
			}
		}
	}
	if view.Findings == nil && withFindings {
		view.Findings = []SiteFinding{}
	}
	return view
}

func (a *Asset) summary() Asset {
	result := *a
	result.RawRequest, result.RawResponse, result.Findings = "", "", nil
	return result
}

func (a *Asset) clone() Asset {
	result := *a
	result.Findings = append([]model.Finding(nil), a.Findings...)
	result.Progress.Plugins = cloneProgress(a.Progress.Plugins)
	return result
}

func (m *Manager) warmAsset(session *Session, assetID string) error {
	session.mu.RLock()
	asset := session.assets[assetID]
	if asset == nil {
		session.mu.RUnlock()
		return errors.New("接口资产不存在")
	}
	cold := asset.Cold
	sessionID := session.id
	session.mu.RUnlock()
	if !cold {
		return nil
	}
	if m.persistence == nil {
		return errors.New("接口完整报文已释放且恢复文件不可用")
	}
	persisted, err := m.persistence.readAsset(sessionID, assetID)
	if err != nil {
		return fmt.Errorf("读取接口恢复文件失败: %w", err)
	}
	session.mu.Lock()
	if current := session.assets[assetID]; current != nil && current.Cold {
		current.RawRequest, current.RawResponse = persisted.RawRequest, persisted.RawResponse
		current.Baseline = persisted.Baseline
		current.Findings = persisted.Findings
		current.Cold = false
	}
	session.mu.Unlock()
	return nil
}

func (m *Manager) coolAsset(sessionID, assetID string) {
	session, ok := m.session(sessionID)
	if !ok {
		return
	}
	session.mu.Lock()
	asset := session.assets[assetID]
	if asset == nil || asset.ScanStatus == "queued" || asset.ScanStatus == "scanning" || asset.ScanStatus == "running" {
		session.mu.Unlock()
		return
	}
	asset.RawRequest, asset.RawResponse = "", ""
	asset.Baseline = model.Response{}
	for index := range asset.Findings {
		asset.Findings[index].Evidence = nil
	}
	asset.Cold = true
	session.mu.Unlock()
}

func fingerprintRequest(r *http.Request, body []byte) (string, string) {
	normalized := normalizePath(r.URL.EscapedPath())
	queryKeys := make([]string, 0, len(r.URL.Query()))
	for key := range r.URL.Query() {
		queryKeys = append(queryKeys, key)
	}
	sort.Strings(queryKeys)
	shape := bodyShape(r.Header.Get("Content-Type"), body)
	if strings.Contains(strings.ToLower(r.URL.Path), "graphql") {
		shape += "|" + graphQLIdentity(body)
	}
	scheme := strings.ToLower(r.URL.Scheme)
	if scheme == "" {
		scheme = "http"
	}
	source := strings.Join([]string{strings.ToUpper(r.Method), scheme, hostname(r.Host), normalized, strings.ToLower(mediaType(r.Header.Get("Content-Type"))), strings.Join(queryKeys, ","), shape}, "\x00")
	sum := sha256.Sum256([]byte(source))
	return "asset_" + hex.EncodeToString(sum[:12]), normalized
}

func graphQLIdentity(body []byte) string {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(body))
	if decoder.Decode(&value) != nil {
		return ""
	}
	var identities []string
	var visit func(any)
	visit = func(candidate any) {
		switch item := candidate.(type) {
		case map[string]any:
			if operation, ok := item["operationName"].(string); ok && operation != "" {
				identities = append(identities, "name:"+operation)
			}
			if query, ok := item["query"].(string); ok {
				fields := strings.Fields(strings.TrimSpace(query))
				if len(fields) > 0 {
					identity := strings.ToLower(fields[0])
					if len(fields) > 1 && (identity == "query" || identity == "mutation" || identity == "subscription") {
						identity += ":" + strings.Trim(fields[1], "({")
					}
					identities = append(identities, identity)
				}
			}
		case []any:
			for _, child := range item {
				visit(child)
			}
		}
	}
	visit(value)
	sort.Strings(identities)
	return strings.Join(identities, ",")
}

func normalizePath(value string) string {
	if value == "" {
		return "/"
	}
	parts := strings.Split(value, "/")
	for index, part := range parts {
		switch {
		case numericPath.MatchString(part):
			parts[index] = "{number}"
		case uuidPath.MatchString(part):
			parts[index] = "{uuid}"
		case hexPath.MatchString(part):
			parts[index] = "{hex}"
		}
	}
	return strings.Join(parts, "/")
}

func bodyShape(contentType string, body []byte) string {
	kind := mediaType(contentType)
	if strings.HasSuffix(kind, "+json") || kind == "application/json" {
		var value any
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.UseNumber()
		if decoder.Decode(&value) == nil {
			var paths []string
			walkJSON(value, "$", &paths)
			sort.Strings(paths)
			return strings.Join(paths, ",")
		}
	}
	if kind == "application/x-www-form-urlencoded" {
		values, _ := url.ParseQuery(string(body))
		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		return strings.Join(keys, ",")
	}
	if kind == "multipart/form-data" {
		_, params, err := mime.ParseMediaType(contentType)
		if err == nil && params["boundary"] != "" {
			reader := multipart.NewReader(bytes.NewReader(body), params["boundary"])
			var fields []string
			for {
				part, readErr := reader.NextPart()
				if readErr != nil {
					break
				}
				label := part.FormName()
				if part.FileName() != "" {
					label += ":file"
				}
				fields = append(fields, label)
				_ = part.Close()
			}
			sort.Strings(fields)
			return strings.Join(fields, ",")
		}
	}
	if kind == "application/xml" || kind == "text/xml" || strings.HasSuffix(kind, "+xml") {
		decoder := xml.NewDecoder(bytes.NewReader(body))
		var stack []string
		var nodes []string
		for {
			token, err := decoder.Token()
			if err != nil {
				break
			}
			switch item := token.(type) {
			case xml.StartElement:
				stack = append(stack, item.Name.Local)
				current := "/" + strings.Join(stack, "/")
				nodes = append(nodes, current)
				for _, attribute := range item.Attr {
					nodes = append(nodes, current+"/@"+attribute.Name.Local)
				}
			case xml.EndElement:
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
			}
		}
		sort.Strings(nodes)
		return strings.Join(nodes, ",")
	}
	return ""
}

func walkJSON(value any, prefix string, paths *[]string) {
	switch item := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(item))
		for key := range item {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			walkJSON(item[key], prefix+"."+key, paths)
		}
	case []any:
		*paths = append(*paths, prefix+"[]")
		if len(item) > 0 {
			walkJSON(item[0], prefix+"[]", paths)
		}
	case json.Number:
		*paths = append(*paths, prefix+":number")
	case string:
		*paths = append(*paths, prefix+":string")
	case bool:
		*paths = append(*paths, prefix+":bool")
	case nil:
		*paths = append(*paths, prefix+":null")
	}
}

func rawRequest(r *http.Request, body []byte) string {
	var builder strings.Builder
	target := r.URL.RequestURI()
	if target == "" {
		target = "/"
	}
	fmt.Fprintf(&builder, "%s %s HTTP/1.1\r\nHost: %s\r\n", r.Method, target, r.Host)
	names := sortedHeaderNames(r.Header)
	for _, name := range names {
		if hopHeaders[strings.ToLower(name)] || strings.EqualFold(name, "Host") || strings.EqualFold(name, "Content-Length") {
			continue
		}
		for _, value := range r.Header.Values(name) {
			fmt.Fprintf(&builder, "%s: %s\r\n", name, value)
		}
	}
	if len(body) > 0 {
		fmt.Fprintf(&builder, "Content-Length: %d\r\n", len(body))
	}
	builder.WriteString("\r\n")
	builder.Write(body)
	return builder.String()
}

func rawResponse(response *http.Response, body []byte, truncated bool) string {
	return rawResponseParts(response.Status, response.Header, body, truncated)
}

func rawResponseParts(status string, header http.Header, body []byte, truncated bool) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "HTTP/1.1 %s\r\n", status)
	for _, name := range sortedHeaderNames(header) {
		if hopHeaders[strings.ToLower(name)] {
			continue
		}
		for _, value := range header.Values(name) {
			fmt.Fprintf(&builder, "%s: %s\r\n", name, value)
		}
	}
	builder.WriteString("\r\n")
	builder.Write(body)
	if truncated {
		builder.WriteString("\n...[proxy response sample truncated]")
	}
	return builder.String()
}

func capturedResponse(response *http.Response, wireBody []byte, wireTruncated bool) ([]byte, http.Header, string, bool) {
	header := response.Header.Clone()
	body := append([]byte(nil), wireBody...)
	truncated := wireTruncated
	contentEncoding := strings.TrimSpace(header.Get("Content-Encoding"))
	if contentEncoding != "" {
		decoded, applied, decodeTruncated, err := responsebody.DecodeContentEncoding(body, contentEncoding, maxResponseBytes)
		header.Del("Content-Encoding")
		header.Del("Content-Length")
		truncated = truncated || decodeTruncated
		if err != nil || !applied {
			message := "[HappyScan 无法解码 Content-Encoding: " + contentEncoding + "]"
			if err != nil {
				message += " " + err.Error()
			}
			body = []byte(message)
			return body, header, "utf-8", true
		}
		body = decoded
	}
	if len(body) > maxResponseBytes {
		body = body[:maxResponseBytes]
		truncated = true
	}
	body, charset := responsebody.Decode(body, header.Get("Content-Type"))
	if charset != "" && charset != "binary" && charset != "utf-8" {
		if contentType, parameters, err := mime.ParseMediaType(header.Get("Content-Type")); err == nil {
			parameters["charset"] = "utf-8"
			header.Set("Content-Type", mime.FormatMediaType(contentType, parameters))
		}
	}
	return body, header, charset, truncated
}

func capturedWireBytes(response *http.Response, captured []byte) int64 {
	if response != nil && response.ContentLength >= 0 {
		return response.ContentLength
	}
	return int64(len(captured))
}

func readBounded(reader io.Reader, limit int) ([]byte, bool, error) {
	data, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if err != nil {
		return nil, false, err
	}
	if len(data) > limit {
		return data, true, nil
	}
	return data, false, nil
}

func requestEditable(contentType string) bool {
	kind := mediaType(contentType)
	return kind == "" || strings.HasPrefix(kind, "text/") ||
		strings.Contains(kind, "json") || strings.Contains(kind, "xml") ||
		kind == "application/x-www-form-urlencoded" || kind == "multipart/form-data"
}

func responseEditable(header http.Header) bool {
	if strings.TrimSpace(header.Get("Content-Encoding")) != "" {
		return false
	}
	return requestEditable(header.Get("Content-Type"))
}

func streamingResponse(response *http.Response) bool {
	return response.StatusCode == http.StatusSwitchingProtocols ||
		strings.EqualFold(strings.TrimSpace(response.Header.Get("Upgrade")), "websocket") ||
		strings.EqualFold(mediaType(response.Header.Get("Content-Type")), "text/event-stream")
}

func writeProxyDrop(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-HappyScan-Intercept", "dropped")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]any{"code": "HAPPYSCAN_INTERCEPT_DROPPED", "message": message})
}

func parseEditedResponse(raw string) (int, http.Header, []byte, error) {
	reader := bufio.NewReader(strings.NewReader(raw))
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return 0, nil, nil, errors.New("缺少完整的 HTTP 状态行")
	}
	statusLine = strings.TrimSpace(statusLine)
	parts := strings.Fields(statusLine)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return 0, nil, nil, errors.New("状态行格式应为 HTTP/x.y STATUS REASON")
	}
	status, err := strconv.Atoi(parts[1])
	if err != nil || status < 100 || status > 599 {
		return 0, nil, nil, errors.New("HTTP 状态码无效")
	}
	header := make(http.Header)
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil && len(line) == 0 {
			return 0, nil, nil, errors.New("响应 Header 未正确结束")
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(name) == "" || strings.ContainsAny(name, " \t\r\n") {
			return 0, nil, nil, fmt.Errorf("HTTP Header 不合法: %q", line)
		}
		header.Add(name, strings.TrimSpace(value))
		if readErr != nil {
			return 0, nil, nil, errors.New("响应 Header 未正确结束")
		}
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		return 0, nil, nil, err
	}
	stripHop(header)
	header.Del("Content-Length")
	return status, header, body, nil
}

// ParseRawResponse parses a captured HTTP response for callers that already
// have the upstream response and want to reuse it as scan baseline evidence.
func ParseRawResponse(raw string) (int, http.Header, []byte, error) {
	return parseEditedResponse(raw)
}

type limitedBuffer struct {
	bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(data []byte) (int, error) {
	original := len(data)
	remaining := b.limit - b.Len()
	if remaining <= 0 {
		b.truncated = true
		return original, nil
	}
	if len(data) > remaining {
		_, _ = b.Buffer.Write(data[:remaining])
		b.truncated = true
		return original, nil
	}
	_, _ = b.Buffer.Write(data)
	return original, nil
}

func copyHeaders(target, source http.Header) {
	for name, values := range source {
		for _, value := range values {
			target.Add(name, value)
		}
	}
}

func responseHeaders(source http.Header) (map[string]string, map[string][]string) {
	headers := make(map[string]string, len(source))
	values := make(map[string][]string, len(source))
	for name, items := range source {
		key := strings.ToLower(name)
		values[key] = append([]string(nil), items...)
		headers[key] = strings.Join(items, ", ")
	}
	return headers, values
}

func stripHop(header http.Header) {
	for name := range header {
		if hopHeaders[strings.ToLower(name)] {
			header.Del(name)
		}
	}
}

func sortedHeaderNames(header http.Header) []string {
	names := make([]string, 0, len(header))
	for name := range header {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func mediaType(value string) string {
	kind, _, err := mime.ParseMediaType(value)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(strings.Split(value, ";")[0]))
	}
	return strings.ToLower(kind)
}

func hostname(authority string) string {
	host := authority
	if parsed, err := url.Parse("//" + authority); err == nil && parsed.Hostname() != "" {
		host = parsed.Hostname()
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

func cloneURL(value *url.URL) *url.URL {
	result := *value
	return &result
}

func terminal(status string) bool {
	return status == "completed" || status == "failed" || status == "cancelled"
}

func highestSeverity(findings []model.Finding) string {
	ranks := map[model.Severity]int{model.SeverityInfo: 1, model.SeverityLow: 2, model.SeverityMedium: 3, model.SeverityHigh: 4, model.SeverityCritical: 5}
	var best model.Severity
	for _, finding := range findings {
		if ranks[finding.Severity] > ranks[best] {
			best = finding.Severity
		}
	}
	return string(best)
}

func cloneProgress(values map[string]model.PluginProgress) map[string]model.PluginProgress {
	if values == nil {
		return nil
	}
	result := make(map[string]model.PluginProgress, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func sortedKeys(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func newID(prefix string) string {
	data := make([]byte, 8)
	_, _ = rand.Read(data)
	return prefix + "_" + hex.EncodeToString(data)
}

func tunnelPair(session *Session, client, target net.Conn) {
	deadline := time.Now().Add(5 * time.Minute)
	_ = client.SetDeadline(deadline)
	_ = target.SetDeadline(deadline)
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(target, client)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, target)
		done <- struct{}{}
	}()
	<-done
	_ = client.Close()
	_ = target.Close()
	<-done
	session.mu.Lock()
	delete(session.tunnelConns, client)
	session.mu.Unlock()
}

func bodyPart(raw string) string {
	if index := strings.Index(raw, "\r\n\r\n"); index >= 0 {
		return raw[index+4:]
	}
	return ""
}
