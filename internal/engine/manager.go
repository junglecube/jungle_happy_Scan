package engine

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"jungle_happy_Scan/internal/callback"
	"jungle_happy_Scan/internal/clientcert"
	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/diff"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
	"jungle_happy_Scan/internal/plugin"
	"jungle_happy_Scan/internal/transport"
)

type Event struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

// ConnectivityResult is the original-request preflight result used by the
// synchronous facade before it creates a scan task.
type ConnectivityResult struct {
	Response                            model.Response
	Request                             *httpraw.Request
	AutoFallback                        bool
	ElapsedMS                           int64
	ClientCertificate                   *tls.Certificate
	NetworkOK                           bool
	AuthValid                           *bool
	Reason                              string
	MatchedRule                         string
	OriginalResponseProvided            bool
	OriginalResponseSimilarity          float64
	OriginalResponseSimilarityThreshold float64
}

type Task struct {
	mu                sync.RWMutex
	id                string
	cfg               config.Config
	request           *httpraw.Request
	autoScheme        bool
	plugins           []plugin.Plugin
	status            string
	createdAt         time.Time
	startedAt         *time.Time
	finishedAt        *time.Time
	findings          []model.Finding
	findingKeys       map[string]struct{}
	correlations      []model.FindingCorrelation
	coverage          model.Coverage
	warnings          []string
	err               string
	progress          model.Progress
	ctx               context.Context
	cancel            context.CancelFunc
	subs              map[int]chan Event
	nextSub           int
	done              chan struct{}
	doneOnce          sync.Once
	preflight         *ConnectivityResult
	clientCertificate *tls.Certificate
	expireCtx         context.Context
	expireCancel      context.CancelFunc
	lastProgressEvent time.Time
}

func (t *Task) ID() string { return t.id }

func (t *Task) View() model.ScanView {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.viewLocked()
}

func (t *Task) viewLocked() model.ScanView {
	elapsedEnd := time.Now()
	if t.finishedAt != nil {
		elapsedEnd = *t.finishedAt
	}
	elapsed := int64(0)
	if t.startedAt != nil {
		elapsed = elapsedEnd.Sub(*t.startedAt).Milliseconds()
	}
	progress := t.progress
	progress.Plugins = make(map[string]model.PluginProgress, len(t.progress.Plugins))
	for id, item := range t.progress.Plugins {
		progress.Plugins[id] = item
	}
	coverage := t.coverage
	coverage.Plugins = make(map[string]model.PluginCoverage, len(t.coverage.Plugins))
	for id, item := range t.coverage.Plugins {
		coverage.Plugins[id] = item
	}
	return model.ScanView{
		ScanID: t.id, Status: t.status, CreatedAt: t.createdAt, StartedAt: t.startedAt,
		FinishedAt: t.finishedAt, ElapsedMS: elapsed, Progress: progress,
		FindingsCount: len(t.findings), Error: t.err, Warnings: append([]string(nil), t.warnings...),
		Coverage: coverage, Correlations: append([]model.FindingCorrelation(nil), t.correlations...),
	}
}

func (t *Task) Findings() []model.Finding {
	t.mu.RLock()
	defer t.mu.RUnlock()
	items := make([]model.Finding, len(t.findings))
	copy(items, t.findings)
	return items
}

// Wait blocks until the scan reaches a terminal state or the caller cancels.
// The scan itself keeps its own lifecycle; HTTP handlers may explicitly cancel it
// when their client disconnects.
func (t *Task) Wait(ctx context.Context) error {
	select {
	case <-t.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *Task) signalDone() {
	t.doneOnce.Do(func() { close(t.done) })
}

func (t *Task) addWarning(message string) {
	t.mu.Lock()
	t.warnings = append(t.warnings, message)
	view := t.viewLocked()
	t.mu.Unlock()
	t.publish(Event{Type: "warning", Data: map[string]string{"message": message}})
	t.publishProgress(view, false)
}

func (t *Task) addFindings(items []model.Finding) {
	t.mu.Lock()
	if t.findingKeys == nil {
		t.findingKeys = make(map[string]struct{})
	}
	added := make([]model.Finding, 0, len(items))
	for _, item := range items {
		key := item.PluginID + "\x00" + item.Affected + "\x00" + item.Title
		if _, exists := t.findingKeys[key]; exists {
			continue
		}
		t.findingKeys[key] = struct{}{}
		item = enrichFinding(item)
		t.findings = append(t.findings, item)
		added = append(added, item)
	}
	t.mu.Unlock()
	for _, item := range added {
		t.publish(Event{Type: "finding", Data: item})
	}
}

func (t *Task) updatePlugin(id, name string, completed, total int) {
	t.mu.Lock()
	t.progress.Plugin = id
	item := t.progress.Plugins[id]
	item.Name = name
	if item.Status == "" || item.Status == "queued" {
		item.Status = "running"
	}
	t.progress.Plugins[id] = item
	view := t.viewLocked()
	t.mu.Unlock()
	t.publishProgress(view, false)
}

func (t *Task) requestProgress(id, name string, used int) {
	t.mu.Lock()
	item := t.progress.Plugins[id]
	item.Name = name
	item.Status = "running"
	item.RequestsSent = used
	item.Completed = min(pluginResolvedRequests(item), item.Total)
	t.progress.Plugin = id
	t.progress.Plugins[id] = item
	t.recalculateRequestProgressLocked()
	view := t.viewLocked()
	t.mu.Unlock()
	t.publishProgress(view, false)
}

func (t *Task) resolvePluginRequests(id, name, kind string, count int) {
	if count <= 0 {
		return
	}
	t.mu.Lock()
	item := t.progress.Plugins[id]
	item.Name = name
	if item.Status == "" || item.Status == "queued" {
		item.Status = "running"
	}
	count = min(count, max(0, item.Total-pluginResolvedRequests(item)))
	switch kind {
	case "adaptive_pruned":
		item.AdaptivePruned += count
	case "mutation_failed":
		item.MutationFailed += count
	case "budget_skipped":
		item.BudgetSkipped += count
	}
	item.Completed = min(pluginResolvedRequests(item), item.Total)
	t.progress.Plugins[id] = item
	t.recalculateRequestProgressLocked()
	view := t.viewLocked()
	t.mu.Unlock()
	t.publishProgress(view, false)
}

func (t *Task) finishPluginProgress(id, name, status string, used int, resolveRemaining bool) {
	t.mu.Lock()
	item := t.progress.Plugins[id]
	item.Name = name
	item.Status = status
	item.RequestsSent = used
	item.Completed = min(pluginResolvedRequests(item), item.Total)
	remaining := max(0, item.Total-item.Completed)
	if resolveRemaining {
		item.AdaptivePruned += remaining
	} else if status == "partial" {
		item.BudgetSkipped += remaining
	}
	item.Completed = min(pluginResolvedRequests(item), item.Total)
	t.progress.Plugins[id] = item
	t.recalculateRequestProgressLocked()
	view := t.viewLocked()
	t.mu.Unlock()
	t.publishProgress(view, false)
}

func (t *Task) recalculateRequestProgressLocked() {
	resolved := 0
	adaptivePruned := 0
	mutationFailures := 0
	budgetSkipped := 0
	for _, item := range t.progress.Plugins {
		resolved += item.Completed
		adaptivePruned += item.AdaptivePruned
		mutationFailures += item.MutationFailed
		budgetSkipped += item.BudgetSkipped
	}
	t.progress.ResolvedRequests = min(resolved, t.progress.PlannedRequests)
	t.progress.AdaptivePruned = adaptivePruned
	t.progress.MutationFailures = mutationFailures
	t.progress.BudgetSkipped = budgetSkipped
	t.progress.RequestsSkipped = adaptivePruned + mutationFailures + budgetSkipped
	t.progress.CompletedChecks = t.progress.ResolvedRequests
	t.progress.TotalChecks = t.progress.PlannedRequests
	if t.progress.PlannedRequests > 0 {
		calculated := 10 + int(float64(t.progress.ResolvedRequests)/float64(t.progress.PlannedRequests)*89)
		t.progress.Percent = max(t.progress.Percent, min(calculated, 99))
	}
}

func pluginResolvedRequests(item model.PluginProgress) int {
	// Resolution describes why every planned slot ended, not whether the slot
	// was covered. BudgetSkipped therefore advances terminal progress while the
	// plugin and overall coverage status remain partial.
	return item.RequestsSent + item.AdaptivePruned + item.MutationFailed + item.BudgetSkipped
}

func (t *Task) publishProgress(view model.ScanView, force bool) {
	t.mu.Lock()
	now := time.Now()
	if !force && !t.lastProgressEvent.IsZero() && now.Sub(t.lastProgressEvent) < 100*time.Millisecond {
		t.mu.Unlock()
		return
	}
	t.lastProgressEvent = now
	t.mu.Unlock()
	t.publish(Event{Type: "progress", Data: view})
}

func (t *Task) requestSent() {
	t.mu.Lock()
	t.progress.RequestsSent++
	t.mu.Unlock()
}

func (t *Task) networkError() {
	t.mu.Lock()
	t.progress.NetworkErrors++
	t.mu.Unlock()
}

func (t *Task) subscribe() (<-chan Event, func()) {
	t.mu.Lock()
	id := t.nextSub
	t.nextSub++
	ch := make(chan Event, 32)
	t.subs[id] = ch
	view := t.viewLocked()
	t.mu.Unlock()
	ch <- Event{Type: "snapshot", Data: view}
	return ch, func() {
		t.mu.Lock()
		if existing, ok := t.subs[id]; ok {
			delete(t.subs, id)
			close(existing)
		}
		t.mu.Unlock()
	}
}

func (t *Task) publish(event Event) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, ch := range t.subs {
		select {
		case ch <- event:
		default:
		}
	}
}

type Manager struct {
	store     *config.Store
	callbacks *callback.Registry
	governor  *transport.Governor
	mu        sync.RWMutex
	tasks     map[string]*Task
	queueMu   sync.Mutex
	queued    int
	queue     chan queuedTask
	slotMu    sync.Mutex
	active    int
	slotEvent chan struct{}
}

type queuedTask struct {
	task *Task
	mode string
}

func NewManager(store *config.Store, callbacks *callback.Registry) *Manager {
	cfg := store.Get()
	manager := &Manager{
		store: store, callbacks: callbacks, tasks: make(map[string]*Task), slotEvent: make(chan struct{}),
		queue:    make(chan queuedTask, 10_000),
		governor: transport.NewGovernor(cfg.GlobalMaxConcurrency, cfg.PerHostConcurrency, cfg.GlobalRequestsPerSecond),
	}
	go manager.dispatch()
	return manager
}

// dispatch is the single bounded queue consumer. It acquires a process task
// slot before spawning work, so 10,000 queued tasks do not become 10,000
// goroutines blocked in acquireSlot.
func (m *Manager) dispatch() {
	for item := range m.queue {
		if !m.acquireSlot(item.task.ctx) {
			m.leaveQueue()
			m.finishCancelled(item.task)
			continue
		}
		go m.run(item.task, item.mode)
	}
}

func baselineSamplesFor(method string, configured int) int {
	if configured < 1 {
		configured = 1
	}
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return configured
	default:
		// Never repeat an unmodified state-changing request merely to estimate
		// response stability. A synchronous preflight already supplies this one
		// baseline; an asynchronous task sends it exactly once.
		return 1
	}
}

// CheckConnectivity sends only the unmodified original request. Auto mode uses
// the same HTTP-first, HTTPS-second fallback as a real scan, including optional
// per-call domain-to-IP overrides.
func (m *Manager) CheckConnectivity(ctx context.Context, input model.ScanInput) (ConnectivityResult, error) {
	cfg := m.store.Get()
	if err := applyHostOverrides(&cfg, input.Host); err != nil {
		return ConnectivityResult{}, err
	}
	scheme, automatic, err := input.ResolveScheme(cfg.DefaultScheme)
	if err != nil {
		return ConnectivityResult{}, err
	}
	request, err := httpraw.Parse(input.RawHTTP(), scheme)
	if err != nil {
		return ConnectivityResult{}, err
	}
	if !automatic {
		request = request.WithScheme(scheme)
	}
	if len(cfg.AllowedHosts) == 0 {
		cfg.AllowedHosts = []string{request.Host()}
	}
	certificate, err := clientcert.FromScanInput(input)
	if err != nil {
		return ConnectivityResult{}, err
	}
	client, err := transport.NewWithGovernorAndCertificate(cfg, transport.Hooks{}, m.governor, certificate)
	if err != nil {
		return ConnectivityResult{}, err
	}
	defer client.Close()
	started := time.Now()
	response, usedRequest, fellBack, err := client.SendWithSchemeFallback(ctx, request, automatic)
	result := ConnectivityResult{Response: response, Request: usedRequest, AutoFallback: fellBack, ElapsedMS: time.Since(started).Milliseconds(), ClientCertificate: certificate}
	if err != nil {
		result.Reason = fmt.Sprintf("原始报文连通性检测失败: %s", transport.FriendlyError(err, cfg.TimeoutSeconds))
		return result, errors.New(result.Reason)
	}
	result.NetworkOK = true
	auth := diff.AuthDenied(response, cfg)
	authValid := !auth.Denied
	result.AuthValid = &authValid
	result.Reason = auth.Reason
	result.MatchedRule = auth.MatchedRule
	return result, nil
}

func (m *Manager) Plan(input model.ScanInput) (model.ScanPlan, error) {
	raw := input.RawHTTP()
	if len(raw) < 10 {
		return model.ScanPlan{}, errors.New("http 字段必须包含完整 HTTP 报文")
	}
	if len(input.SelectedPlugins()) == 0 {
		return model.ScanPlan{}, errors.New("scan_type 至少选择一种漏洞类型")
	}
	cfg := m.store.Get()
	if err := applyHostOverrides(&cfg, input.Host); err != nil {
		return model.ScanPlan{}, err
	}
	scheme, automatic, err := input.ResolveScheme(cfg.DefaultScheme)
	if err != nil {
		return model.ScanPlan{}, err
	}
	mode := input.SelectedMode()
	if mode == "" {
		mode = cfg.ScanMode
	}
	if mode != "passive" && mode != "normal" && mode != "standard" && mode != "deep" {
		return model.ScanPlan{}, errors.New("mode 必须是 passive、normal、standard 或 deep")
	}
	request, err := httpraw.Parse(raw, scheme)
	if err != nil {
		return model.ScanPlan{}, err
	}
	if !automatic {
		request = request.WithScheme(scheme)
	}
	selected, err := plugin.Select(input.SelectedPlugins(), mode)
	if err != nil {
		return model.ScanPlan{}, err
	}
	points := httpraw.DiscoverAdvanced(request, cfg)
	baselineSamples := baselineSamplesFor(request.Method, cfg.BaselineSamples)
	budget := max(0, cfg.MaxRequests-baselineSamples)
	plans := plugin.BuildExecutionPlans(selected, request, points, mode, cfg, budget)
	preview := model.ScanPlan{
		Mode: mode, Method: request.Method, DiscoveredPoints: len(points), RequestBudget: budget,
		Plugins: make(map[string]model.PluginCoverage, len(plans)),
	}
	if requestURL, parseErr := request.URL(); parseErr == nil {
		preview.URL = requestURL
	}
	for _, plan := range plans {
		meta := plan.Plugin.Meta()
		status := "planned"
		if !plan.Applicable {
			status = "skipped"
		} else {
			preview.EstimatedRequests += plan.EstimatedRequests
			if plan.Budget < plan.EstimatedRequests {
				status = "partial"
			}
		}
		preview.Plugins[meta.ID] = model.PluginCoverage{
			Name: meta.Name, Status: status, Applicable: plan.Applicable, Reason: plan.Reason,
			PointsTotal: plan.PointsTotal, EstimatedRequests: plan.EstimatedRequests, RequestBudget: plan.Budget,
		}
	}
	preview.CompleteWithinBudget = preview.EstimatedRequests <= budget
	rate := math.Max(1, cfg.RequestsPerSecond)
	preview.EstimatedSeconds = int(math.Ceil(float64(preview.EstimatedRequests) / rate))
	preview.EstimatedSeconds += baselineSamples
	return preview, nil
}

func (m *Manager) Create(input model.ScanInput) (*Task, error) {
	return m.create(input, nil)
}

// CreateWithPreflight reuses a successful original-request connectivity check
// as the first baseline. This avoids sending a state-changing original request
// twice through the synchronous facade.
func (m *Manager) CreateWithPreflight(input model.ScanInput, preflight ConnectivityResult) (*Task, error) {
	return m.create(input, &preflight)
}

func (m *Manager) create(input model.ScanInput, preflight *ConnectivityResult) (*Task, error) {
	// Serialize the logical queue capacity check with task insertion. Individual
	// map locks alone are race-free but would let concurrent callers all observe
	// the same free slot before any of them inserted a task.
	m.queueMu.Lock()
	defer m.queueMu.Unlock()
	raw := input.RawHTTP()
	if len(raw) < 10 {
		return nil, errors.New("http 字段必须包含完整 HTTP 报文")
	}
	selectedIDs := input.SelectedPlugins()
	if len(selectedIDs) == 0 {
		return nil, errors.New("scan_type 至少选择一种漏洞类型")
	}
	cfg := m.store.Get()
	if m.queued >= cfg.MaxQueuedScans {
		return nil, errors.New("扫描队列已满，请稍后重试")
	}
	if err := applyHostOverrides(&cfg, input.Host); err != nil {
		return nil, err
	}
	scheme, autoScheme, err := input.ResolveScheme(cfg.DefaultScheme)
	if err != nil {
		return nil, err
	}
	mode := input.Mode
	if mode == "" {
		mode = input.ScanMode
	}
	if mode == "" {
		mode = cfg.ScanMode
	}
	if mode != "passive" && mode != "normal" && mode != "standard" && mode != "deep" {
		return nil, errors.New("mode 必须是 passive、normal、standard 或 deep")
	}
	request, err := httpraw.Parse(raw, scheme)
	if err != nil {
		return nil, err
	}
	if !autoScheme {
		request = request.WithScheme(scheme)
	}
	selected, err := plugin.Select(selectedIDs, mode)
	if err != nil {
		return nil, err
	}
	if len(cfg.AllowedHosts) == 0 {
		cfg.AllowedHosts = []string{request.Host()}
	}
	var certificate *tls.Certificate
	if preflight != nil && preflight.ClientCertificate != nil {
		certificate = preflight.ClientCertificate
	} else {
		certificate, err = clientcert.FromScanInput(input)
		if err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	expireCtx, expireCancel := context.WithCancel(context.Background())
	task := &Task{
		id: newID("scan"), cfg: cfg, request: request, autoScheme: autoScheme, plugins: selected,
		status: "queued", createdAt: time.Now().UTC(), ctx: ctx, cancel: cancel,
		subs:              make(map[int]chan Event),
		done:              make(chan struct{}),
		progress:          model.Progress{Phase: "queued", Plugins: make(map[string]model.PluginProgress)},
		coverage:          model.Coverage{Plugins: make(map[string]model.PluginCoverage)},
		findingKeys:       make(map[string]struct{}),
		preflight:         preflight,
		clientCertificate: certificate,
		expireCtx:         expireCtx, expireCancel: expireCancel,
	}
	if preflight != nil && preflight.Request != nil {
		task.request = preflight.Request.Clone()
		task.autoScheme = false
	}
	for _, item := range selected {
		meta := item.Meta()
		task.progress.Plugins[meta.ID] = model.PluginProgress{Name: meta.Name, Total: 1, Status: "queued"}
	}
	m.mu.Lock()
	m.tasks[task.id] = task
	m.mu.Unlock()
	m.queued++
	// The channel is sized to the validated hard maximum. This defensive branch
	// keeps map/count state consistent if that invariant is ever changed.
	select {
	case m.queue <- queuedTask{task: task, mode: mode}:
	default:
		m.queued--
		m.mu.Lock()
		delete(m.tasks, task.id)
		m.mu.Unlock()
		task.cancel()
		task.expireCancel()
		return nil, errors.New("扫描队列已满，请稍后重试")
	}
	return task, nil
}

func applyHostOverrides(cfg *config.Config, values map[string]string) error {
	if len(values) == 0 {
		return nil
	}
	if len(values) > 100 {
		return errors.New("host 映射不能超过 100 项")
	}
	if cfg.ProxyURL != "" {
		return errors.New("host 映射不能与显式 HTTP 代理同时使用")
	}
	cfg.HostOverrides = make(map[string]string, len(values))
	for name, address := range values {
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
		ip := net.ParseIP(strings.TrimSpace(address))
		if host == "" || strings.ContainsAny(host, "\r\n/: ") || ip == nil {
			return fmt.Errorf("host 映射 %q=%q 无效，Key 必须是域名且 Value 必须是 IP", name, address)
		}
		cfg.HostOverrides[host] = ip.String()
	}
	return nil
}

func (m *Manager) Get(id string) (*Task, bool) {
	m.mu.RLock()
	task, ok := m.tasks[id]
	m.mu.RUnlock()
	return task, ok
}

func (m *Manager) Cancel(id string) bool {
	task, ok := m.Get(id)
	if !ok {
		return false
	}
	task.cancel()
	return true
}

func (m *Manager) Delete(id string) bool {
	m.mu.Lock()
	task, ok := m.tasks[id]
	if ok {
		delete(m.tasks, id)
	}
	m.mu.Unlock()
	if ok {
		task.cancel()
		task.expireCancel()
	}
	return ok
}

func (m *Manager) Subscribe(id string) (<-chan Event, func(), bool) {
	task, ok := m.Get(id)
	if !ok {
		return nil, nil, false
	}
	ch, cancel := task.subscribe()
	return ch, cancel, true
}

func (m *Manager) Callbacks() *callback.Registry { return m.callbacks }

func (m *Manager) run(task *Task, mode string) {
	m.leaveQueue()
	defer m.releaseSlot()
	now := time.Now().UTC()
	task.mu.Lock()
	task.status = "running"
	task.startedAt = &now
	task.progress.Phase = "baseline"
	task.progress.Percent = 2
	preflight := task.preflight
	task.preflight = nil
	task.mu.Unlock()
	task.publishProgress(task.View(), true)
	client, err := transport.NewWithGovernorAndCertificate(task.cfg, transport.Hooks{OnRequest: task.requestSent, OnError: task.networkError}, m.governor, task.clientCertificate)
	task.clientCertificate = nil
	if err != nil {
		m.finishFailed(task, err)
		return
	}
	defer client.Close()
	baselineSamples := baselineSamplesFor(task.request.Method, task.cfg.BaselineSamples)
	baselines := make([]model.Response, 0, baselineSamples)
	baselineStart := 0
	if preflight != nil && preflight.Request != nil && preflight.Response.StatusCode > 0 {
		baselines = append(baselines, preflight.Response)
		baselineStart = 1
		if len(task.cfg.ResponseExtractors) > 0 {
			updated, applied := httpraw.ApplyResponseExtractors(task.request, preflight.Response, task.cfg.ResponseExtractors)
			if len(applied) > 0 {
				task.request = updated
				task.addWarning("已从连通性响应刷新动态值：" + strings.Join(applied, "、"))
			}
		}
	}
	// The potentially large response/request retained by the synchronous
	// preflight is now represented by baselines and task.request.
	preflight = nil
	for i := baselineStart; i < baselineSamples; i++ {
		response, usedRequest, fellBack, sendErr := client.SendWithSchemeFallback(task.ctx, task.request, task.autoScheme && i == 0)
		if sendErr != nil {
			if errors.Is(sendErr, context.Canceled) {
				m.finishCancelled(task)
			} else {
				m.finishFailed(task, fmt.Errorf("基线请求失败: %s", transport.FriendlyError(sendErr, task.cfg.TimeoutSeconds)))
			}
			return
		}
		if usedRequest != nil {
			task.request = usedRequest.Clone()
		}
		if task.autoScheme && i == 0 {
			task.autoScheme = false
		}
		if fellBack {
			task.addWarning("HTTP 连通性探测失败，已自动切换为 HTTPS，后续扫描沿用 HTTPS。")
		}
		baselines = append(baselines, response)
		if i == 0 && len(task.cfg.ResponseExtractors) > 0 {
			updated, applied := httpraw.ApplyResponseExtractors(task.request, response, task.cfg.ResponseExtractors)
			if len(applied) > 0 {
				task.request = updated
				task.addWarning("已从基线响应刷新动态值：" + strings.Join(applied, "、"))
			}
		}
		task.mu.Lock()
		task.progress.Percent = 2 + int(float64(i+1)/float64(baselineSamples)*8)
		task.mu.Unlock()
	}
	stability := diff.BaselineStability(baselines, task.cfg)
	if stability < 0.75 {
		task.addWarning(fmt.Sprintf("基线响应稳定度较低（%.2f），主动差分结果会更保守", stability))
	}
	points := httpraw.DiscoverAdvanced(task.request, task.cfg)
	representativeBaseline := baselines[diff.RepresentativeBaselineIndex(baselines, task.cfg)]
	sendFunc := client.Send
	if len(task.cfg.ResponseExtractors) > 0 {
		var sessionMu sync.Mutex
		sessionValues := httpraw.ExtractResponseValues(baselines[len(baselines)-1], task.cfg.ResponseExtractors)
		parallelSafe := true
		for _, extractor := range task.cfg.ResponseExtractors {
			if !extractor.ParallelSafe {
				parallelSafe = false
				break
			}
		}
		sendFunc = func(ctx context.Context, request *httpraw.Request) (model.Response, error) {
			// Single-use CSRF/nonces require one atomic apply-send-extract cycle.
			// Administrators may opt all extractors into snapshot concurrency only
			// when the target accepts reuse or independently rotated values.
			if !parallelSafe {
				sessionMu.Lock()
				defer sessionMu.Unlock()
				updated, applyErr := httpraw.ApplyDestinationValues(request, sessionValues)
				if applyErr != nil {
					return model.Response{}, fmt.Errorf("应用轮换会话值失败: %w", applyErr)
				}
				response, sendErr := client.Send(ctx, updated)
				if sendErr == nil {
					for destination, value := range httpraw.ExtractResponseValues(response, task.cfg.ResponseExtractors) {
						sessionValues[destination] = value
					}
				}
				return response, sendErr
			}
			sessionMu.Lock()
			snapshot := make(map[string]string, len(sessionValues))
			for destination, value := range sessionValues {
				snapshot[destination] = value
			}
			sessionMu.Unlock()
			updated, applyErr := httpraw.ApplyDestinationValues(request, snapshot)
			if applyErr != nil {
				return model.Response{}, fmt.Errorf("应用轮换会话值失败: %w", applyErr)
			}
			response, sendErr := client.Send(ctx, updated)
			if sendErr == nil {
				extracted := httpraw.ExtractResponseValues(response, task.cfg.ResponseExtractors)
				sessionMu.Lock()
				for destination, value := range extracted {
					sessionValues[destination] = value
				}
				sessionMu.Unlock()
			}
			return response, sendErr
		}
	}
	availableBudget := max(0, task.cfg.MaxRequests-baselineSamples)
	plans := plugin.BuildExecutionPlans(task.plugins, task.request, points, mode, task.cfg, availableBudget)
	allocatedBudget := 0
	for _, plan := range plans {
		allocatedBudget += plan.Budget
	}
	// The static planner guarantees a fair initial share. Runtime pruning often
	// leaves much of that share unused, especially after a clean SQL gate. Keep
	// the remainder in a task-local pool so later plugins can reclaim it instead
	// of being marked partial while global capacity is still available.
	sharedBudget := max(0, availableBudget-allocatedBudget)
	var sharedBudgetMu sync.Mutex
	task.mu.Lock()
	task.progress.Phase = "scanning"
	task.progress.Percent = 10
	task.coverage.DiscoveredPoints = len(points)
	task.coverage.RequestBudget = availableBudget
	task.coverage.PlannedRequests = 0
	task.progress.PlannedRequests = 0
	task.progress.ResolvedRequests = 0
	task.progress.RequestsSkipped = 0
	for _, plan := range plans {
		meta := plan.Plugin.Meta()
		if plan.Applicable {
			task.coverage.PlannedRequests += plan.EstimatedRequests
			task.progress.PlannedRequests += plan.EstimatedRequests
			task.progress.Plugins[meta.ID] = model.PluginProgress{Name: meta.Name, Total: plan.EstimatedRequests, Status: "queued"}
		}
		status := "queued"
		if !plan.Applicable {
			status = "skipped"
			task.coverage.PluginsSkipped++
		}
		task.coverage.Plugins[meta.ID] = model.PluginCoverage{
			Name: meta.Name, Status: status, Applicable: plan.Applicable, Reason: plan.Reason,
			PointsTotal: plan.PointsTotal, EstimatedRequests: plan.EstimatedRequests, RequestBudget: plan.Budget,
		}
		if !plan.Applicable {
			task.progress.Plugins[meta.ID] = model.PluginProgress{Name: meta.Name, Status: "skipped"}
		}
	}
	task.mu.Unlock()
	executePlan := func(plan plugin.ExecutionPlan) int {
		item := plan.Plugin
		meta := item.Meta()
		if !plan.Applicable {
			return 0
		}
		sharedBudgetMu.Lock()
		if need := plan.EstimatedRequests - plan.Budget; need > 0 && sharedBudget > 0 {
			extra := min(need, sharedBudget)
			quantum := plugin.PlanBudgetQuantum(meta.ID)
			extra -= extra % quantum
			if extra > 0 {
				plan.Budget += extra
				sharedBudget -= extra
			}
		}
		sharedBudgetMu.Unlock()
		releaseUnusedBudget := func(used int) {
			if unused := max(0, plan.Budget-used); unused > 0 {
				sharedBudgetMu.Lock()
				sharedBudget += unused
				sharedBudgetMu.Unlock()
			}
		}
		task.mu.Lock()
		coverageBudget := task.coverage.Plugins[meta.ID]
		coverageBudget.RequestBudget = plan.Budget
		task.coverage.Plugins[meta.ID] = coverageBudget
		task.mu.Unlock()
		if plan.EstimatedRequests > 0 && plan.Budget == 0 {
			task.mu.Lock()
			entry := task.coverage.Plugins[meta.ID]
			entry.Status = "partial"
			entry.Reason = "全局请求预算不足"
			task.coverage.Plugins[meta.ID] = entry
			task.coverage.PluginsPartial++
			task.mu.Unlock()
			task.finishPluginProgress(meta.ID, meta.Name, "partial", 0, false)
			return 0
		}
		ctx := &plugin.Context{
			Context: task.ctx, Request: task.request, Baselines: baselines, Baseline: representativeBaseline,
			Points: points, Mode: mode, Config: task.cfg, Callbacks: m.callbacks,
			SendFunc:      sendFunc,
			Progress:      func(id string, completed, total int) { task.updatePlugin(id, meta.Name, completed, total) },
			OnRequest:     func(used int) { task.requestProgress(meta.ID, meta.Name, used) },
			OnResolution:  func(kind string, count int) { task.resolvePluginRequests(meta.ID, meta.Name, kind, count) },
			RequestBudget: plan.Budget,
		}
		findings, scanErr := item.Scan(ctx)
		used, exhausted := ctx.BudgetState()
		if scanErr != nil && !errors.Is(scanErr, context.Canceled) && !errors.Is(scanErr, plugin.ErrPluginBudgetExhausted) {
			task.addWarning(meta.Name + ": " + scanErr.Error())
		}
		if len(findings) > 0 {
			task.addFindings(findings)
		}
		task.mu.Lock()
		coverage := task.coverage.Plugins[meta.ID]
		coverage.RequestsSent = used
		progressItem := task.progress.Plugins[meta.ID]
		coverage.AdaptivePruned = progressItem.AdaptivePruned
		coverage.MutationFailed = progressItem.MutationFailed
		coverage.BudgetSkipped = progressItem.BudgetSkipped
		task.coverage.RequestsSent += used
		if scanErr != nil && !errors.Is(scanErr, plugin.ErrPluginBudgetExhausted) && !errors.Is(scanErr, context.Canceled) {
			coverage.Status = "failed"
			coverage.Reason = scanErr.Error()
			task.coverage.PluginsFailed++
		} else if exhausted || errors.Is(scanErr, plugin.ErrPluginBudgetExhausted) {
			coverage.Status = "partial"
			coverage.Reason = "插件公平请求预算已用尽"
			if plan.EstimatedRequests > 0 {
				coverage.PointsCompleted = min(plan.PointsTotal, int(float64(plan.PointsTotal)*float64(used)/float64(plan.EstimatedRequests)))
			}
			task.coverage.PluginsPartial++
		} else if progressItem.MutationFailed > 0 || progressItem.BudgetSkipped > 0 {
			coverage.Status = "partial"
			switch {
			case progressItem.MutationFailed > 0 && progressItem.BudgetSkipped > 0:
				coverage.Reason = "部分插入点变异失败，且部分请求因预算未执行"
			case progressItem.MutationFailed > 0:
				coverage.Reason = "部分插入点无法安全变异"
			default:
				coverage.Reason = "部分请求因预算未执行"
			}
			if plan.EstimatedRequests > 0 {
				covered := max(0, used+progressItem.AdaptivePruned)
				coverage.PointsCompleted = min(plan.PointsTotal, int(float64(plan.PointsTotal)*float64(covered)/float64(plan.EstimatedRequests)))
			}
			task.coverage.PluginsPartial++
		} else {
			coverage.Status = "completed"
			coverage.PointsCompleted = plan.PointsTotal
			task.coverage.PluginsCompleted++
		}
		task.coverage.Plugins[meta.ID] = coverage
		task.mu.Unlock()
		status := coverage.Status
		task.finishPluginProgress(meta.ID, meta.Name, status, used, status == "completed")
		task.mu.Lock()
		progressItem = task.progress.Plugins[meta.ID]
		coverage = task.coverage.Plugins[meta.ID]
		coverage.AdaptivePruned = progressItem.AdaptivePruned
		coverage.MutationFailed = progressItem.MutationFailed
		coverage.BudgetSkipped = progressItem.BudgetSkipped
		task.coverage.Plugins[meta.ID] = coverage
		task.mu.Unlock()
		releaseUnusedBudget(used)
		return used
	}

	// V2 staged scheduling prevents passive analysis, out-of-band probes and
	// state-changing requests from interfering with one another. Safe phases
	// retain concurrency; state-changing plugins run exclusively.
	for phase := 0; phase < 4; phase++ {
		phaseName := []string{"passive_analysis", "safe_active", "oast_confirmation", "state_changing"}[phase]
		task.mu.Lock()
		task.progress.Phase = phaseName
		task.mu.Unlock()
		var phasePlans []plugin.ExecutionPlan
		for _, plan := range plans {
			if planStage(plan.Plugin.Meta()) == phase {
				phasePlans = append(phasePlans, plan)
			}
		}
		if phase == 3 {
			for _, plan := range phasePlans {
				executePlan(plan)
				if task.ctx.Err() != nil {
					break
				}
			}
			continue
		}
		// All SQL-family plugins share one exclusive oracle lane. This keeps
		// quote recovery, Boolean, timing and clause A-B-B-A observations from
		// being interleaved with cache-, session- or rate-limit-affecting probes.
		// Other safe-active plugins retain normal concurrency after that lane.
		var concurrentPlans []plugin.ExecutionPlan
		for _, plan := range phasePlans {
			if sqlOracleLane(plan.Plugin.Meta().ID) {
				executePlan(plan)
				if task.ctx.Err() != nil {
					break
				}
				continue
			}
			concurrentPlans = append(concurrentPlans, plan)
		}
		if task.ctx.Err() != nil {
			break
		}
		var wg sync.WaitGroup
		for _, plan := range concurrentPlans {
			plan := plan
			wg.Add(1)
			go func() {
				defer wg.Done()
				executePlan(plan)
			}()
		}
		wg.Wait()
	}
	if task.ctx.Err() != nil {
		m.finishCancelled(task)
		return
	}
	finished := time.Now().UTC()
	task.mu.Lock()
	task.status = "completed"
	task.finishedAt = &finished
	task.progress.Phase = "completed"
	task.progress.Percent = 100
	task.progress.Plugin = ""
	task.findings, task.correlations = deduplicateAndCorrelate(task.findings)
	task.coverage.Complete = task.coverage.PluginsPartial == 0 && task.coverage.PluginsFailed == 0
	view := task.viewLocked()
	task.mu.Unlock()
	task.signalDone()
	task.publish(Event{Type: "done", Data: view})
	go m.expire(task.expireCtx, task.id, task.cfg.TaskTTLMinutes)
}

func (m *Manager) leaveQueue() {
	m.queueMu.Lock()
	if m.queued > 0 {
		m.queued--
	}
	m.queueMu.Unlock()
}

func planStage(meta model.PluginMeta) int {
	if meta.Risk == "passive" {
		return 0
	}
	switch meta.ID {
	case "ssrf", "xxe_extended", "command_injection_oast", "jndi_injection":
		return 2
	}
	if meta.Risk == "state-changing" {
		return 3
	}
	return 1
}

func sqlOracleLane(id string) bool {
	switch id {
	case "sqli", "sqli_extended", "sqli_timing", "sqli_order_by", "sqli_limit", "mybatis_dynamic_sql":
		return true
	default:
		return false
	}
}

func (m *Manager) acquireSlot(ctx context.Context) bool {
	for {
		m.slotMu.Lock()
		limit := m.store.Get().MaxActiveScans
		if m.active < limit {
			m.active++
			m.slotMu.Unlock()
			return true
		}
		event := m.slotEvent
		m.slotMu.Unlock()
		select {
		case <-ctx.Done():
			return false
		case <-event:
		}
	}
}

func (m *Manager) releaseSlot() {
	m.slotMu.Lock()
	if m.active > 0 {
		m.active--
	}
	close(m.slotEvent)
	m.slotEvent = make(chan struct{})
	m.slotMu.Unlock()
}

func (m *Manager) finishFailed(task *Task, err error) {
	finished := time.Now().UTC()
	task.mu.Lock()
	task.status = "failed"
	task.err = err.Error()
	task.finishedAt = &finished
	task.progress.Phase = "failed"
	view := task.viewLocked()
	task.mu.Unlock()
	task.signalDone()
	task.publish(Event{Type: "done", Data: view})
	go m.expire(task.expireCtx, task.id, task.cfg.TaskTTLMinutes)
}

func (m *Manager) finishCancelled(task *Task) {
	finished := time.Now().UTC()
	task.mu.Lock()
	task.status = "cancelled"
	task.finishedAt = &finished
	task.progress.Phase = "cancelled"
	view := task.viewLocked()
	task.mu.Unlock()
	task.signalDone()
	task.publish(Event{Type: "done", Data: view})
	go m.expire(task.expireCtx, task.id, task.cfg.TaskTTLMinutes)
}

func (m *Manager) expire(ctx context.Context, id string, ttlMinutes int) {
	timer := time.NewTimer(time.Duration(ttlMinutes) * time.Minute)
	defer timer.Stop()
	select {
	case <-timer.C:
		m.Delete(id)
	case <-ctx.Done():
	}
}

func newID(prefix string) string {
	raw := make([]byte, 16)
	_, _ = rand.Read(raw)
	return prefix + "_" + hex.EncodeToString(raw)
}
