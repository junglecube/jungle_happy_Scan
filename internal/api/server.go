package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"jungle_happy_Scan/internal/callback"
	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/engine"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
	"jungle_happy_Scan/internal/plugin"
	"jungle_happy_Scan/internal/webscan"
)

type Server struct {
	store          *config.Store
	manager        *engine.Manager
	static         fs.FS
	logger         *slog.Logger
	configPassword []byte
	rateMu         sync.Mutex
	scanRates      map[string]scanRateWindow
	rateLastSweep  time.Time
	clientTLSDir   string
	webScans       *webscan.Manager
	replayMu       sync.RWMutex
	replays        map[string]*replayTask
}

type scanRateWindow struct {
	Started time.Time
	Count   int
}

func New(store *config.Store, manager *engine.Manager, logger *slog.Logger) (*Server, error) {
	static, err := fs.Sub(webAssets, "web")
	if err != nil {
		return nil, err
	}
	password := os.Getenv("JUNGLE_CONFIG_PASSWORD")
	if password == "" {
		password = "jungle"
		logger.Warn("JUNGLE_CONFIG_PASSWORD 未设置，兼容使用默认配置密码；共享部署应通过环境变量覆盖")
	}
	clientTLSDir, err := filepath.Abs(filepath.Join(filepath.Dir(store.Path()), "client_tls_files"))
	if err != nil {
		return nil, fmt.Errorf("解析客户端证书目录失败: %w", err)
	}
	server := &Server{
		store: store, manager: manager, static: static, logger: logger,
		configPassword: []byte(password), scanRates: make(map[string]scanRateWindow), rateLastSweep: time.Now(),
		clientTLSDir: clientTLSDir, replays: make(map[string]*replayTask),
	}
	stateBase := filepath.Dir(store.Path())
	if filepath.Base(stateBase) == "config" {
		stateBase = filepath.Join(filepath.Dir(stateBase), "var")
	}
	stateDir, err := filepath.Abs(filepath.Join(stateBase, "webscan_state"))
	if err != nil {
		return nil, fmt.Errorf("解析WEB扫描恢复目录失败: %w", err)
	}
	server.webScans = webscan.NewPersistent(engineScannerAdapter{manager: manager}, logger, stateDir)
	return server, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.health)
	mux.HandleFunc("GET /api/v1/plugins", s.plugins)
	mux.HandleFunc("GET /api/v2/plugins", s.pluginsV2)
	mux.HandleFunc("GET /api/v1/config", s.getConfig)
	mux.HandleFunc("PUT /api/v1/config", s.putConfig)
	mux.HandleFunc("POST /api/v1/parse", s.parse)
	mux.HandleFunc("POST /api/v1/plan", s.plan)
	mux.HandleFunc("POST /api/v1/connectivity", s.connectivity)
	mux.HandleFunc("/api/v1/replays", s.replayCollection)
	mux.HandleFunc("/api/v1/replays/", s.replayRoute)
	mux.HandleFunc("POST /api/v1/client-tls-files", s.uploadClientTLSFile)
	mux.HandleFunc("GET /api/v3/proxy-ca", s.proxyCACertificate)
	mux.HandleFunc("POST /api/v1/scan", s.createScan)
	mux.HandleFunc("POST /api/v1/scans", s.createScan)
	mux.HandleFunc("POST /api/v1/jungle_happy_scan", s.jungleHappyScan)
	mux.HandleFunc("POST /jungle_happy_scan", s.jungleHappyScan)
	mux.HandleFunc("POST /api/v1/jungle_happy_scan_lite", s.jungleHappyScanLite)
	mux.HandleFunc("POST /jungle_happy_scan_lite", s.jungleHappyScanLite)
	mux.HandleFunc("POST /api/v2/jungle_happy_scan", s.jungleHappyScanV2)
	mux.HandleFunc("POST /api/v2/jungle_happy_scan_lite", s.jungleHappyScanLiteV2)
	mux.HandleFunc("/api/v3/web-scans", s.webScanCollection)
	mux.HandleFunc("/api/v3/web-scans/", s.webScanRoute)
	mux.HandleFunc("/api/v1/scans/", s.scanRoute)
	mux.HandleFunc("/", s.web)
	return s.middleware(mux)
}

func (s *Server) proxyCACertificate(w http.ResponseWriter, _ *http.Request) {
	certificate, err := s.webScans.RootCertificate()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "无法读取 HappyScan HTTPS 代理 CA")
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="jungle_happy_Scan-proxy-ca.pem"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(certificate)
}

func (s *Server) Close() {
	if s.webScans != nil {
		s.webScans.Close()
	}
	s.closeReplays()
}

type engineScannerAdapter struct {
	manager *engine.Manager
}

func (a engineScannerAdapter) Start(input model.ScanInput, baseline model.Response) (string, error) {
	request, err := httpraw.Parse(input.RawHTTP(), "http")
	if err != nil {
		return "", err
	}
	task, err := a.manager.CreateWithPreflight(input, engine.ConnectivityResult{
		Request: request, Response: baseline,
	})
	if err != nil {
		return "", err
	}
	return task.ID(), nil
}

func (a engineScannerAdapter) Snapshot(id string) (model.ScanView, []model.Finding, bool) {
	task, ok := a.manager.Get(id)
	if !ok {
		return model.ScanView{}, nil, false
	}
	return task.View(), task.Findings(), true
}

func (a engineScannerAdapter) Cancel(id string) bool {
	return a.manager.Cancel(id)
}

func (s *Server) webScanCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"api_version": "3.5", "web_scans": s.webScans.List()})
	case http.MethodPost:
		var input webscan.SessionConfig
		if err := decodeJSON(w, r, &input, 1_000_000); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		mode := strings.ToLower(strings.TrimSpace(input.ScanMode))
		if mode == "" {
			mode = "passive"
		}
		if mode != "passive" && mode != "normal" && mode != "deep" {
			writeError(w, http.StatusBadRequest, "scan_mode 必须是 passive、normal 或 deep")
			return
		}
		input.ScanMode = mode
		globalScope := strings.TrimSpace(input.TargetURL) == "" || strings.TrimSpace(input.TargetURL) == "*"
		if globalScope && mode != "passive" {
			writeError(w, http.StatusBadRequest, "全局作用域只允许使用 passive 模式")
			return
		}
		if len(input.Plugins) == 0 {
			ids, err := plugin.PresetIDsWithNormal(mode, s.store.Get().NormalPlugins)
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			input.Plugins = ids
		} else {
			selected, err := plugin.Select(input.Plugins, mode)
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			if globalScope {
				for _, item := range selected {
					if item.Meta().Risk != "passive" {
						writeError(w, http.StatusBadRequest, "全局作用域只允许被动扫描插件")
						return
					}
				}
			}
		}
		created, err := s.webScans.Create(input)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"api_version": "3.5", "web_scan": created})
	default:
		w.Header().Set("Allow", "GET, POST")
		writeError(w, http.StatusMethodNotAllowed, "只支持 GET 或 POST")
	}
}

func (s *Server) webScanRoute(w http.ResponseWriter, r *http.Request) {
	pathValue := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v3/web-scans/"), "/")
	parts := strings.Split(pathValue, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusNotFound, "WEB扫描任务不存在")
		return
	}
	sessionID := parts[0]
	switch {
	case len(parts) == 2 && sessionID == "history" && parts[1] == "changes" && r.Method == http.MethodGet:
		since, _ := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
		revision := s.webScans.WaitChanges(r.Context(), since, 25*time.Second)
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, map[string]any{"api_version": "3.5", "revision": revision})
	case len(parts) == 2 && sessionID == "history" && parts[1] == "assets" && r.Method == http.MethodGet:
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
		if page < 1 {
			page = 1
		}
		if pageSize < 1 {
			pageSize = 50
		}
		assets, total := s.webScans.HistoricalAssetsPage(
			r.URL.Query().Get("q"), r.URL.Query().Get("status"), page, pageSize,
		)
		writeJSON(w, http.StatusOK, map[string]any{
			"api_version": "3.5", "assets": assets, "page": page,
			"page_size": min(max(pageSize, 1), 100), "total": total,
		})
	case len(parts) == 2 && sessionID == "history" && parts[1] == "assets" && r.Method == http.MethodDelete:
		var input struct {
			Confirm string `json:"confirm"`
		}
		if err := decodeJSON(w, r, &input, 10_000); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if input.Confirm != "CLEAR_ALL_HISTORY_ASSETS" {
			writeError(w, http.StatusBadRequest, "缺少清空全部历史资产的确认标识")
			return
		}
		removed := s.webScans.ClearHistoricalAssets()
		writeJSON(w, http.StatusOK, map[string]any{"api_version": "3.5", "removed": removed})
	case len(parts) == 2 && sessionID == "history" && parts[1] == "findings" && r.Method == http.MethodGet:
		groups, findings := s.webScans.HistoricalFindingReport(r.URL.Query().Get("group"))
		writeJSON(w, http.StatusOK, map[string]any{
			"api_version": "3.5", "groups": groups, "findings": findings,
		})
	case len(parts) == 1 && sessionID == "browser-heartbeat" && r.Method == http.MethodPost:
		var input struct {
			BrowserOwner string `json:"browser_owner"`
		}
		if err := decodeJSON(w, r, &input, 10_000); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.webScans.TouchBrowserOwner(input.BrowserOwner)
		w.WriteHeader(http.StatusNoContent)
	case len(parts) == 1 && sessionID == "browser-close" && r.Method == http.MethodPost:
		var input struct {
			BrowserOwner string `json:"browser_owner"`
		}
		if err := decodeJSON(w, r, &input, 10_000); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.webScans.ScheduleBrowserCleanup(input.BrowserOwner)
		w.WriteHeader(http.StatusAccepted)
	case len(parts) == 1 && r.Method == http.MethodGet:
		session, ok := s.webScans.Summary(sessionID)
		if !ok {
			writeError(w, http.StatusNotFound, "WEB扫描任务不存在")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"api_version": "3.5", "web_scan": session})
	case len(parts) == 1 && r.Method == http.MethodDelete:
		if !s.webScans.Delete(sessionID) {
			writeError(w, http.StatusNotFound, "WEB扫描任务不存在")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case len(parts) == 2 && parts[1] == "proxy" && r.Method == http.MethodDelete:
		if !s.webScans.StopProxy(sessionID) {
			writeError(w, http.StatusNotFound, "WEB扫描任务不存在")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case len(parts) == 2 && parts[1] == "interception" && r.Method == http.MethodPut:
		var input webscan.InterceptionSettings
		if err := decodeJSON(w, r, &input, 10_000); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		session, err := s.webScans.UpdateInterception(sessionID, input)
		if err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"api_version": "3.5", "web_scan": session})
	case len(parts) == 2 && parts[1] == "interceptions" && r.Method == http.MethodGet:
		since, _ := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
		wait := time.Duration(0)
		if r.URL.Query().Get("wait") == "1" {
			wait = 25 * time.Second
		}
		items, revision, ok := s.webScans.WaitInterceptions(r.Context(), sessionID, since, wait)
		if !ok {
			writeError(w, http.StatusNotFound, "WEB扫描任务不存在")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, map[string]any{"api_version": "3.5", "revision": revision, "interceptions": items})
	case len(parts) == 3 && parts[1] == "interceptions" && r.Method == http.MethodGet:
		item, ok := s.webScans.Interception(sessionID, parts[2])
		if !ok {
			writeError(w, http.StatusNotFound, "拦截项不存在")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"api_version": "3.5", "interception": item})
	case len(parts) == 4 && parts[1] == "interceptions" && (parts[3] == "forward" || parts[3] == "drop") && r.Method == http.MethodPost:
		var input struct {
			Raw string `json:"raw"`
		}
		if err := decodeJSON(w, r, &input, 11_000_000); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.webScans.Decide(sessionID, parts[2], parts[3], input.Raw); err != nil {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		w.WriteHeader(http.StatusAccepted)
	case len(parts) == 2 && parts[1] == "assets" && r.Method == http.MethodGet:
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
		if page < 1 {
			page = 1
		}
		if pageSize < 1 {
			pageSize = 50
		}
		assets, total, ok := s.webScans.AssetsPage(sessionID, r.URL.Query().Get("q"), r.URL.Query().Get("status"), page, pageSize)
		if !ok {
			writeError(w, http.StatusNotFound, "WEB扫描任务不存在")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"api_version": "3.5", "assets": assets, "page": page,
			"page_size": min(max(pageSize, 1), 100), "total": total,
		})
	case len(parts) == 2 && parts[1] == "findings" && r.Method == http.MethodGet:
		findings, ok := s.webScans.FindingSummaries(sessionID)
		if !ok {
			writeError(w, http.StatusNotFound, "WEB扫描任务不存在")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"api_version": "3.5", "findings": findings})
	case len(parts) == 3 && parts[1] == "assets" && r.Method == http.MethodGet:
		asset, ok := s.webScans.Asset(sessionID, parts[2])
		if !ok {
			writeError(w, http.StatusNotFound, "接口资产不存在")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"api_version": "3.5", "asset": asset, "findings": asset.Findings})
	case len(parts) == 4 && parts[1] == "assets" && parts[3] == "scan" && r.Method == http.MethodPost:
		if err := s.webScans.Scan(sessionID, parts[2]); err != nil {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"asset_id": parts[2], "status": "queued"})
	default:
		writeError(w, http.StatusNotFound, "接口不存在")
	}
}

func (s *Server) uploadClientTLSFile(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 2_200_000)
	if err := r.ParseMultipartForm(2_200_000); err != nil {
		writeError(w, http.StatusBadRequest, "客户端 TLS 证书上传失败或超过 2 MiB")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "缺少名为 file 的证书文件")
		return
	}
	defer file.Close()
	extension := strings.ToLower(filepath.Ext(header.Filename))
	if extension != ".pem" && extension != ".pfx" && extension != ".p12" {
		writeError(w, http.StatusBadRequest, "客户端 TLS 证书仅支持 .pem、.pfx、.p12")
		return
	}
	data, err := io.ReadAll(io.LimitReader(file, 2_000_001))
	if err != nil || len(data) == 0 || len(data) > 2_000_000 {
		writeError(w, http.StatusBadRequest, "客户端 TLS 证书大小必须在 1 字节到 2 MiB 之间")
		return
	}
	defer clear(data)
	if err := os.MkdirAll(s.clientTLSDir, 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, "无法创建客户端 TLS 证书目录")
		return
	}
	originalName := filepath.Base(header.Filename)
	if originalName == "." || originalName == string(filepath.Separator) || originalName == "" ||
		strings.ContainsAny(originalName, "\r\n\x00") {
		writeError(w, http.StatusBadRequest, "客户端 TLS 证书文件名无效")
		return
	}
	target := filepath.Join(s.clientTLSDir, originalName)
	handle, err := os.CreateTemp(s.clientTLSDir, ".client-tls-upload-*")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "无法保存客户端 TLS 证书")
		return
	}
	tempName := handle.Name()
	defer os.Remove(tempName)
	if err = handle.Chmod(0o600); err != nil {
		_ = handle.Close()
		writeError(w, http.StatusInternalServerError, "无法设置客户端 TLS 证书权限")
		return
	}
	if _, err = handle.Write(data); err == nil {
		err = handle.Sync()
	}
	closeErr := handle.Close()
	if err != nil || closeErr != nil {
		writeError(w, http.StatusInternalServerError, "无法完整保存客户端 TLS 证书")
		return
	}
	if err := os.Rename(tempName, target); err != nil {
		writeError(w, http.StatusInternalServerError, "无法替换客户端 TLS 证书")
		return
	}
	s.logger.Info("client TLS certificate uploaded", "file", target, "size", len(data))
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_tls_file": target,
		"format":          strings.TrimPrefix(extension, "."),
		"filename":        originalName,
	})
}

// CallbackHandler exposes only the one-time callback endpoint on the dedicated
// listener. Scanner management and scan creation APIs remain on the main port.
func (s *Server) CallbackHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/callback/", s.callback)
	mux.HandleFunc("/api/v1/callback", s.callback)
	mux.HandleFunc("/callback/", s.callback)
	mux.HandleFunc("/callback", s.callback)
	return mux
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		defer func() {
			if recovered := recover(); recovered != nil {
				s.logger.Error("http handler panic", "path", r.URL.Path, "error", recovered)
				writeError(w, http.StatusInternalServerError, "服务器内部错误")
			}
		}()
		if isScanCreationPath(r.URL.Path) && r.Method == http.MethodPost && !s.allowScanRequest(r) {
			writeError(w, http.StatusTooManyRequests, "调用方每分钟扫描任务数已达到限制")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "service": "jungle_happy_Scan", "time": time.Now().UTC()})
}

func (s *Server) plugins(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"plugins": plugin.Metadata()})
}

func (s *Server) pluginsV2(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"api_version": "2.0", "rule_pack_version": "2.4.0", "rule_pack_digest": s.rulePackDigest(), "plugins": plugin.Metadata()})
}

func (s *Server) getConfig(w http.ResponseWriter, r *http.Request) {
	current := s.store.Get()
	if !clientAllowedByCIDR(r, current.ConfigWriteAllowedCIDRs) {
		writeError(w, http.StatusForbidden, "当前来源 IP 不允许读取持久配置")
		return
	}
	for index := range current.RequestTransforms {
		if current.RequestTransforms[index].Secret != "" {
			current.RequestTransforms[index].Secret = "<redacted>"
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"config": current, "config_file": s.store.Path()})
}

func (s *Server) putConfig(w http.ResponseWriter, r *http.Request) {
	if !clientAllowedByCIDR(r, s.store.Get().ConfigWriteAllowedCIDRs) {
		writeError(w, http.StatusForbidden, "当前来源 IP 不允许修改持久配置")
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Jungle-Config-Password")), s.configPassword) != 1 {
		writeError(w, http.StatusForbidden, "配置保存密码错误")
		return
	}
	var cfg config.Config
	if err := decodeJSON(w, r, &cfg, 1_000_000); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	previous := s.store.Get()
	for index := range cfg.RequestTransforms {
		if cfg.RequestTransforms[index].Secret != "<redacted>" {
			continue
		}
		for _, oldRule := range previous.RequestTransforms {
			if oldRule.Name == cfg.RequestTransforms[index].Name && oldRule.Algorithm == cfg.RequestTransforms[index].Algorithm {
				cfg.RequestTransforms[index].Secret = oldRule.Secret
				break
			}
		}
	}
	oldListen := previous.Listen
	oldCallbackListen := previous.CallbackListen
	oldLDAPListen := previous.CallbackLDAPListen
	oldCallbackMaxConnections := previous.CallbackMaxConnections
	if err := s.store.Save(cfg); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	persisted := s.store.Get()
	for index := range persisted.RequestTransforms {
		if persisted.RequestTransforms[index].Secret != "" {
			persisted.RequestTransforms[index].Secret = "<redacted>"
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"config": persisted, "saved": true, "config_file": s.store.Path(),
		"restart_required": oldListen != cfg.Listen || oldCallbackListen != cfg.CallbackListen || oldLDAPListen != cfg.CallbackLDAPListen ||
			oldCallbackMaxConnections != cfg.CallbackMaxConnections ||
			previous.GlobalMaxConcurrency != cfg.GlobalMaxConcurrency || previous.PerHostConcurrency != cfg.PerHostConcurrency ||
			previous.GlobalRequestsPerSecond != cfg.GlobalRequestsPerSecond,
	})
}

func isScanCreationPath(path string) bool {
	return path == "/api/v1/scan" || path == "/api/v1/scans" ||
		path == "/api/v1/jungle_happy_scan" || path == "/jungle_happy_scan" ||
		path == "/api/v1/jungle_happy_scan_lite" || path == "/jungle_happy_scan_lite" ||
		path == "/api/v2/jungle_happy_scan" || path == "/api/v2/jungle_happy_scan_lite"
}

func (s *Server) allowScanRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	now := time.Now()
	limit := s.store.Get().MaxScansPerMinute
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	// Sweep on time rather than only after the map becomes very large. A shared
	// service can otherwise retain one stale entry per caller indefinitely while
	// remaining below the old 10,000-entry threshold.
	if now.Sub(s.rateLastSweep) >= time.Minute {
		for address, candidate := range s.scanRates {
			if now.Sub(candidate.Started) >= time.Minute {
				delete(s.scanRates, address)
			}
		}
		s.rateLastSweep = now
	}
	window := s.scanRates[host]
	if window.Started.IsZero() || now.Sub(window.Started) >= time.Minute {
		window = scanRateWindow{Started: now}
	}
	if window.Count >= limit {
		s.scanRates[host] = window
		return false
	}
	window.Count++
	s.scanRates[host] = window
	return true
}

func clientAllowedByCIDR(r *http.Request, cidrs []string) bool {
	if len(cidrs) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, value := range cidrs {
		_, network, err := net.ParseCIDR(value)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Server) parse(w http.ResponseWriter, r *http.Request) {
	var input model.ScanInput
	if err := decodeJSON(w, r, &input, 6_000_000); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	cfg := s.store.Get()
	scheme, autoScheme, err := input.ResolveScheme(cfg.DefaultScheme)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	request, err := httpraw.Parse(input.RawHTTP(), scheme)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !autoScheme {
		request = request.WithScheme(scheme)
	}
	requestURL, _ := request.URL()
	writeJSON(w, http.StatusOK, map[string]any{
		"method": request.Method, "url": requestURL, "host": request.Host(),
		"content_type": request.ContentType(), "insertion_points": httpraw.DiscoverAdvanced(request, cfg),
	})
}

func (s *Server) plan(w http.ResponseWriter, r *http.Request) {
	var input model.ScanInput
	if err := decodeJSON(w, r, &input, 6_000_000); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	preview, err := s.manager.Plan(input)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

func (s *Server) connectivity(w http.ResponseWriter, r *http.Request) {
	var input model.ScanInput
	if err := decodeJSON(w, r, &input, 6_000_000); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	result, sendErr := s.manager.CheckConnectivity(r.Context(), input)
	usedScheme := input.Scheme
	if result.Request != nil {
		usedScheme = result.Request.Scheme
	}
	if sendErr != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": false, "error": sendErr.Error(),
			"elapsed_ms": result.ElapsedMS, "scheme": usedScheme, "auto_fallback": result.AutoFallback,
		})
		return
	}
	response := result.Response
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "elapsed_ms": response.Elapsed.Milliseconds(), "scheme": result.Request.Scheme,
		"auto_fallback": result.AutoFallback, "url": response.URL, "status_code": response.StatusCode,
		"headers": response.Headers, "header_values": response.HeaderValues, "body": responseBodyForDisplay(response.Body),
		"raw_response": rawResponseForDisplay(response),
	})
}

func responseBodyForDisplay(body []byte) string {
	const limit = 200_000
	if len(body) <= limit {
		return string(body)
	}
	return string(body[:limit]) + "\n...[response truncated at 200000 bytes]"
}

func rawResponseForDisplay(response model.Response) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "HTTP/1.1 %d %s\r\n", response.StatusCode, http.StatusText(response.StatusCode))
	names := make([]string, 0, len(response.Headers))
	for name := range response.Headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, value := range response.HeaderAll(name) {
			fmt.Fprintf(&builder, "%s: %s\r\n", name, value)
		}
	}
	builder.WriteString("\r\n")
	builder.WriteString(responseBodyForDisplay(response.Body))
	return builder.String()
}

func synchronousConnectivityView(result engine.ConnectivityResult, sendErr error) map[string]any {
	usedScheme := ""
	if result.Request != nil {
		usedScheme = result.Request.Scheme
	}
	view := map[string]any{
		"ok":            sendErr == nil,
		"network_ok":    result.NetworkOK,
		"scheme":        usedScheme,
		"auto_fallback": result.AutoFallback,
		"elapsed_ms":    result.ElapsedMS,
		"reason":        "",
	}
	if sendErr != nil {
		view["reason"] = "transport_error"
		view["error"] = sendErr.Error()
		return view
	}
	view["status_code"] = result.Response.StatusCode
	if result.AuthValid != nil {
		view["auth_valid"] = *result.AuthValid
	}
	if result.Reason != "" {
		view["reason"] = result.Reason
	}
	if result.MatchedRule != "" {
		view["matched_rule"] = result.MatchedRule
	}
	if result.AuthValid != nil && !*result.AuthValid {
		view["ok"] = false
		view["error"] = "原始报文鉴权预检失败：响应命中 " + result.MatchedRule
	}
	return view
}

func (s *Server) createScan(w http.ResponseWriter, r *http.Request) {
	var input model.ScanInput
	if err := decodeJSON(w, r, &input, 6_000_000); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	task, err := s.manager.Create(input)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.logger.Info("scan task created", "scan_id", task.ID(), "remote", r.RemoteAddr, "plugins", len(input.SelectedPlugins()))
	writeJSON(w, http.StatusAccepted, map[string]any{"scan_id": task.ID(), "status": "queued"})
}

// jungleHappyScan is the synchronous facade for API consumers that do not want
// to create a task and poll multiple endpoints themselves. It deliberately uses
// the same manager and task implementation as the asynchronous API.
func (s *Server) jungleHappyScan(w http.ResponseWriter, r *http.Request) {
	s.jungleHappyScanResponse(w, r, false, false)
}

// jungleHappyScanLite uses the same scan pipeline and input contract, but
// excludes full raw request/response messages from every evidence item.
func (s *Server) jungleHappyScanLite(w http.ResponseWriter, r *http.Request) {
	s.jungleHappyScanResponse(w, r, true, false)
}

func (s *Server) jungleHappyScanV2(w http.ResponseWriter, r *http.Request) {
	s.jungleHappyScanResponse(w, r, false, true)
}

func (s *Server) jungleHappyScanLiteV2(w http.ResponseWriter, r *http.Request) {
	s.jungleHappyScanResponse(w, r, true, true)
}

func (s *Server) jungleHappyScanResponse(w http.ResponseWriter, r *http.Request, lite, apiV2 bool) {
	var external jungleHappyScanInput
	if err := decodeJSON(w, r, &external, 6_000_000); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	input, err := external.scanInput(s.store.Get().NormalPlugins)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Validate plugin selection, Host overrides, raw message and configured
	// execution mode before sending the original request.
	if _, err := s.manager.Plan(input); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	preflight, err := s.manager.CheckConnectivity(r.Context(), input)
	if err != nil {
		now := time.Now().UTC()
		usedScheme := input.Scheme
		if preflight.Request != nil {
			usedScheme = preflight.Request.Scheme
		}
		failed := model.ScanView{
			Status: "failed", CreatedAt: now, FinishedAt: &now, ElapsedMS: preflight.ElapsedMS,
			Error: err.Error(), Warnings: []string{},
			Progress: model.Progress{Phase: "connectivity_failed", Percent: 100, NetworkErrors: 1, Plugins: map[string]model.PluginProgress{}},
			Coverage: model.Coverage{Complete: false, Plugins: map[string]model.PluginCoverage{}},
		}
		result := map[string]any{
			"scan": failed, "findings": []model.Finding{},
			"connectivity": func() map[string]any {
				view := synchronousConnectivityView(preflight, err)
				if usedScheme != "" {
					view["scheme"] = usedScheme
				}
				return view
			}(),
		}
		if apiV2 {
			result["api_version"] = "2.0"
			result["rule_pack_version"] = "2.4.0"
			result["rule_pack_digest"] = s.rulePackDigest()
			result["findings"] = []v2Finding{}
		}
		writeJSON(w, http.StatusOK, result)
		return
	}
	if preflight.AuthValid != nil && !*preflight.AuthValid {
		now := time.Now().UTC()
		message := "原始报文鉴权预检失败：响应命中 " + preflight.MatchedRule
		failed := model.ScanView{
			Status: "failed", CreatedAt: now, FinishedAt: &now, ElapsedMS: preflight.ElapsedMS,
			Error: message, Warnings: []string{},
			Progress: model.Progress{Phase: "connectivity_auth_failed", Percent: 100, Plugins: map[string]model.PluginProgress{}},
			Coverage: model.Coverage{Complete: false, Plugins: map[string]model.PluginCoverage{}},
		}
		result := map[string]any{
			"scan": failed, "findings": []model.Finding{},
			"connectivity": synchronousConnectivityView(preflight, nil),
		}
		if apiV2 {
			result["api_version"] = "2.0"
			result["rule_pack_version"] = "2.4.0"
			result["rule_pack_digest"] = s.rulePackDigest()
			result["findings"] = []v2Finding{}
		}
		writeJSON(w, http.StatusOK, result)
		return
	}
	// Pin the task to the protocol proven by the preflight. This avoids repeating
	// the failed leg of Auto for every baseline request.
	input.Scheme = preflight.Request.Scheme
	task, err := s.manager.CreateWithPreflight(input, preflight)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.logger.Info("synchronous scan created", "scan_id", task.ID(), "remote", r.RemoteAddr, "plugins", len(input.SelectedPlugins()))
	if err := task.Wait(r.Context()); err != nil {
		s.manager.Cancel(task.ID())
		return
	}
	// A completed HTTP call always returns the terminal task snapshot, including
	// failed/cancelled scans. API consumers therefore need only this endpoint and
	// can branch on scan.status without losing diagnostics or partial findings.
	view := task.View()
	findings := task.Findings()
	if lite && !apiV2 {
		findings = liteFindings(findings)
	}
	s.manager.Delete(task.ID())
	result := map[string]any{
		"scan": view, "findings": findings,
		"connectivity": synchronousConnectivityView(preflight, nil),
	}
	if apiV2 {
		result["api_version"] = "2.0"
		result["rule_pack_version"] = "2.4.0"
		result["rule_pack_digest"] = s.rulePackDigest()
		result["findings"] = convertV2Findings(findings, lite)
	}
	writeJSON(w, http.StatusOK, result)
}

type v2Finding struct {
	ID              string           `json:"id"`
	PluginID        string           `json:"plugin_id"`
	Title           string           `json:"title"`
	Severity        string           `json:"severity"`
	SeverityLabel   string           `json:"severity_label"`
	Confidence      string           `json:"confidence"`
	ConfidenceLabel string           `json:"confidence_label"`
	Affected        string           `json:"affected"`
	Description     string           `json:"description"`
	Remediation     string           `json:"remediation"`
	Evidence        []model.Evidence `json:"evidence"`
	References      []string         `json:"references,omitempty"`
	DetectedAt      time.Time        `json:"detected_at"`
	Category        string           `json:"category"`
	CategoryLabel   string           `json:"category_label"`
	Score           int              `json:"score"`
	CorrelationID   string           `json:"correlation_id,omitempty"`
}

func convertV2Findings(findings []model.Finding, lite bool) []v2Finding {
	result := make([]v2Finding, 0, len(findings))
	for _, finding := range findings {
		evidence := append([]model.Evidence(nil), finding.Evidence...)
		if lite {
			for index := range evidence {
				evidence[index].Request = ""
				evidence[index].RequestBase64 = ""
				evidence[index].Response = ""
			}
		}
		result = append(result, v2Finding{
			ID: finding.ID, PluginID: finding.PluginID, Title: finding.Title,
			Severity: severityCode(finding.Severity), SeverityLabel: string(finding.Severity),
			Confidence: confidenceCode(finding.Confidence), ConfidenceLabel: string(finding.Confidence),
			Affected: finding.Affected, Description: finding.Description, Remediation: finding.Remediation,
			Evidence: evidence, References: append([]string(nil), finding.References...), DetectedAt: finding.DetectedAt,
			Category: categoryCode(finding.Category), CategoryLabel: finding.Category,
			Score: finding.Score, CorrelationID: finding.Correlation,
		})
	}
	return result
}

func categoryCode(value string) string {
	switch value {
	case "确认漏洞":
		return "confirmed"
	case "疑似漏洞":
		return "probable"
	case "配置暴露":
		return "exposure"
	case "信息提示":
		return "informational"
	default:
		return "unknown"
	}
}

func (s *Server) rulePackDigest() string {
	cfg := s.store.Get()
	payload, _ := json.Marshal(struct {
		PluginRules     map[string]config.PluginRuleConfig `json:"plugin_rules"`
		SuccessPatterns []string                           `json:"success_patterns"`
		DeniedPatterns  []string                           `json:"denied_patterns"`
		DynamicPatterns []string                           `json:"dynamic_patterns"`
	}{cfg.PluginRules, cfg.SuccessPatterns, cfg.DeniedPatterns, cfg.DynamicPatterns})
	sum := sha256.Sum256(payload)
	return fmt.Sprintf("sha256:%x", sum[:12])
}

func severityCode(value model.Severity) string {
	switch value {
	case model.SeverityInfo:
		return "info"
	case model.SeverityLow:
		return "low"
	case model.SeverityMedium:
		return "medium"
	case model.SeverityHigh:
		return "high"
	case model.SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

func confidenceCode(value model.Confidence) string {
	switch value {
	case model.ConfidenceTentative:
		return "tentative"
	case model.ConfidenceFirm:
		return "firm"
	case model.ConfidenceCertain:
		return "certain"
	default:
		return "unknown"
	}
}

func liteFindings(findings []model.Finding) []model.Finding {
	result := make([]model.Finding, len(findings))
	for index, finding := range findings {
		result[index] = finding
		result[index].Evidence = make([]model.Evidence, len(finding.Evidence))
		for evidenceIndex, evidence := range finding.Evidence {
			evidence.Request = ""
			evidence.RequestBase64 = ""
			evidence.Response = ""
			result[index].Evidence[evidenceIndex] = evidence
		}
	}
	return result
}

type jungleHappyScanInput struct {
	HTTP              string            `json:"http"`
	HTTPBase64        string            `json:"http_base64"`
	ScanType          []string          `json:"scan_type"`
	Scheme            string            `json:"scheme"`
	Host              map[string]string `json:"host"`
	ClientTLSFile     string            `json:"client_tls_file,omitempty"`
	ClientTLSPassword string            `json:"client_tls_password,omitempty"`
}

func (input jungleHappyScanInput) scanInput(configuredNormal ...[]string) (model.ScanInput, error) {
	var normalPlugins []string
	if len(configuredNormal) > 0 {
		normalPlugins = configuredNormal[0]
	}
	rawHTTP, err := input.rawHTTP()
	if err != nil {
		return model.ScanInput{}, err
	}
	if len(input.ScanType) == 0 {
		input.ScanType = []string{"normal"}
	}
	scheme := strings.ToLower(strings.TrimSpace(input.Scheme))
	if scheme == "" {
		scheme = "auto"
	}
	result := model.ScanInput{HTTP: rawHTTP, ScanType: append([]string(nil), input.ScanType...), Scheme: scheme, Host: cloneHostOverrides(input.Host), ClientTLSFile: input.ClientTLSFile, ClientTLSPassword: input.ClientTLSPassword, Mode: "standard"}
	if len(input.ScanType) == 1 {
		preset := strings.ToLower(strings.TrimSpace(input.ScanType[0]))
		if preset == "passive" || preset == "normal" || preset == "deep" {
			ids, err := plugin.PresetIDsWithNormal(preset, normalPlugins)
			if err != nil {
				return model.ScanInput{}, err
			}
			result.ScanType = ids
			result.Mode = preset
		}
	}
	return result, nil
}

const maxRawHTTPBytes = 5_000_000

func (input jungleHappyScanInput) rawHTTP() (string, error) {
	hasHTTP := strings.TrimSpace(input.HTTP) != ""
	hasBase64 := strings.TrimSpace(input.HTTPBase64) != ""
	if hasHTTP == hasBase64 {
		return "", errors.New("http 与 http_base64 必须且只能提供一个")
	}
	if hasHTTP {
		return input.HTTP, nil
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(input.HTTPBase64)
	if err != nil {
		return "", errors.New("http_base64 不是合法的标准 Base64")
	}
	if len(raw) == 0 {
		return "", errors.New("http_base64 解码后不能为空")
	}
	if len(raw) > maxRawHTTPBytes {
		return "", fmt.Errorf("http_base64 解码后的 HTTP 报文超过 %d 字节限制", maxRawHTTPBytes)
	}
	return string(raw), nil
}

func cloneHostOverrides(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string]string, len(values))
	for name, address := range values {
		result[name] = address
	}
	return result
}

func (s *Server) scanRoute(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/scans/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusNotFound, "扫描任务不存在")
		return
	}
	id := parts[0]
	task, ok := s.manager.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "扫描任务不存在或已过期")
		return
	}
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	switch {
	case r.Method == http.MethodGet && action == "":
		writeJSON(w, http.StatusOK, task.View())
	case r.Method == http.MethodGet && (action == "findings" || action == "result"):
		writeJSON(w, http.StatusOK, map[string]any{"scan": task.View(), "findings": task.Findings()})
	case r.Method == http.MethodGet && action == "events":
		s.events(w, r, id)
	case r.Method == http.MethodPost && action == "cancel":
		s.manager.Cancel(id)
		writeJSON(w, http.StatusAccepted, map[string]any{"scan_id": id, "status": "cancelling"})
	case r.Method == http.MethodDelete && action == "":
		s.manager.Delete(id)
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, http.StatusNotFound, "接口不存在")
	}
}

func (s *Server) events(w http.ResponseWriter, r *http.Request, id string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "当前 HTTP 服务不支持 SSE")
		return
	}
	ch, unsubscribe, ok := s.manager.Subscribe(id)
	if !ok {
		writeError(w, http.StatusNotFound, "扫描任务不存在")
		return
	}
	defer unsubscribe()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case event, open := <-ch:
			if !open {
				return
			}
			data, _ := json.Marshal(event.Data)
			_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Type, data)
			flusher.Flush()
			if event.Type == "done" {
				return
			}
		case <-heartbeat.C:
			_, _ = io.WriteString(w, ": heartbeat\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, HEAD, POST")
		writeError(w, http.StatusMethodNotAllowed, "只支持 GET、HEAD 或 POST")
		return
	}
	var token string
	for _, candidate := range callback.TokensFromText(r.URL.Path + "?" + r.URL.RawQuery) {
		if s.manager.Callbacks().Hit(candidate) {
			token = candidate
			break
		}
	}
	if token == "" {
		writeError(w, http.StatusNotFound, "callback token 不存在或已过期")
		return
	}
	// Some Java clients POST the original business request body to the supplied
	// domain. Record the unguessable one-time token before draining the bounded
	// body so even a large POST still proves the outbound request.
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if _, err := io.Copy(io.Discard, r.Body); err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "callback Body 超过 64 KiB")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, token+"\n"+callback.ResponseMarker(token))
	}
}

func (s *Server) web(w http.ResponseWriter, r *http.Request) {
	// OAST callbacks are intentionally served only by CallbackHandler on the
	// dedicated listener. Do not let the SPA fallback on port 8888 turn a wrong
	// callback URL into a misleading HTTP 200.
	if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/callback/") {
		writeError(w, http.StatusNotFound, "接口不存在")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusMethodNotAllowed, "只支持 GET")
		return
	}
	// URL paths and embed.FS always use forward slashes. filepath.Clean uses
	// the host OS separator, which turns /styles.css into \styles.css on
	// Windows and makes every embedded CSS/JS lookup fall back to index.html.
	asset := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if asset == "." || asset == "" || asset == "settings" {
		asset = "index.html"
	}
	data, err := fs.ReadFile(s.static, asset)
	if err != nil {
		data, err = fs.ReadFile(s.static, "index.html")
		asset = "index.html"
	}
	if err != nil {
		writeError(w, http.StatusNotFound, "页面不存在")
		return
	}
	contentType := mime.TypeByExtension(path.Ext(asset))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	// CodeMirror 6 sets a small amount of runtime layout/style information on
	// editor nodes (cursor, measurements, scrolling). Allow inline styles while
	// keeping scripts, connections, images, and framing restricted to this app.
	w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodHead {
		_, _ = w.Write(data)
	}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any, maxBytes int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("JSON 请求无效: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("JSON 请求只能包含一个对象")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": message, "status": status})
}
