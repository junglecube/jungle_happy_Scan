package plugin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"jungle_happy_Scan/internal/callback"
	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/diff"
	evidenceview "jungle_happy_Scan/internal/evidence"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

type Plugin interface {
	Meta() model.PluginMeta
	Scan(*Context) ([]model.Finding, error)
}

type Context struct {
	Context       context.Context
	Request       *httpraw.Request
	Baselines     []model.Response
	Baseline      model.Response
	Points        []httpraw.InsertionPoint
	Mode          string
	Config        config.Config
	Callbacks     *callback.Registry
	SendFunc      func(context.Context, *httpraw.Request) (model.Response, error)
	Progress      func(pluginID string, completed, total int)
	OnRequest     func(used int)
	OnResolution  func(kind string, count int)
	RequestBudget int
	budgetMu      sync.Mutex
	requestsUsed  int
	requestsHeld  int
	budgetHit     bool
}

func (c *Context) Send(request *httpraw.Request) (model.Response, error) {
	c.budgetMu.Lock()
	// A zero budget means "unlimited" for direct plugin callers and unit tests.
	// The engine does not schedule active plugins whose planned budget is zero.
	if c.RequestBudget > 0 && c.requestsUsed+c.requestsHeld >= c.RequestBudget {
		c.budgetHit = true
		c.budgetMu.Unlock()
		return model.Response{}, ErrPluginBudgetExhausted
	}
	c.requestsUsed++
	used := c.requestsUsed
	c.budgetMu.Unlock()
	if c.OnRequest != nil {
		c.OnRequest(used)
	}
	return c.SendFunc(c.Context, request)
}

var ErrPluginBudgetExhausted = errors.New("插件公平请求预算已用尽")

// RequestCohort is an atomic reservation for a paired oracle such as SQL
// A-B-B-A. Reserving the complete group before its first request prevents a
// budget boundary from producing a misleading half-observation.
//
// Callers must Close the cohort. Unsent reservations are returned to the
// plugin-local budget, while requests already sent remain accounted normally.
type RequestCohort struct {
	ctx       *Context
	mu        sync.Mutex
	remaining int
	closed    bool
}

func (c *Context) ReserveCohort(size int) (*RequestCohort, error) {
	if size <= 0 {
		return nil, errors.New("请求组大小必须大于 0")
	}
	c.budgetMu.Lock()
	if c.RequestBudget > 0 && c.requestsUsed+c.requestsHeld+size > c.RequestBudget {
		c.budgetHit = true
		c.budgetMu.Unlock()
		c.ResolveBudgetSkipped(size)
		return nil, ErrPluginBudgetExhausted
	}
	c.requestsHeld += size
	c.budgetMu.Unlock()
	return &RequestCohort{ctx: c, remaining: size}, nil
}

func (r *RequestCohort) Send(request *httpraw.Request) (model.Response, error) {
	r.mu.Lock()
	if r.closed || r.remaining <= 0 {
		r.mu.Unlock()
		return model.Response{}, errors.New("请求组已关闭或没有剩余请求")
	}
	r.remaining--
	r.mu.Unlock()

	r.ctx.budgetMu.Lock()
	if r.ctx.requestsHeld > 0 {
		r.ctx.requestsHeld--
	}
	r.ctx.requestsUsed++
	used := r.ctx.requestsUsed
	r.ctx.budgetMu.Unlock()
	if r.ctx.OnRequest != nil {
		r.ctx.OnRequest(used)
	}
	return r.ctx.SendFunc(r.ctx.Context, request)
}

func (r *RequestCohort) Close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	remaining := r.remaining
	r.remaining = 0
	r.mu.Unlock()
	if remaining == 0 {
		return
	}
	r.ctx.budgetMu.Lock()
	r.ctx.requestsHeld = max(0, r.ctx.requestsHeld-remaining)
	r.ctx.budgetMu.Unlock()
}

func (c *Context) ResolveAdaptivePruned(count int) {
	c.resolveRequests("adaptive_pruned", count)
}

func (c *Context) ResolveMutationFailed(count int) {
	c.resolveRequests("mutation_failed", count)
}

func (c *Context) ResolveBudgetSkipped(count int) {
	c.resolveRequests("budget_skipped", count)
}

func (c *Context) resolveRequests(kind string, count int) {
	if count > 0 && c.OnResolution != nil {
		c.OnResolution(kind, count)
	}
}

func (c *Context) BudgetState() (used int, exhausted bool) {
	c.budgetMu.Lock()
	defer c.budgetMu.Unlock()
	return c.requestsUsed, c.budgetHit
}

func (c *Context) Mutate(point httpraw.InsertionPoint, value string) (*httpraw.Request, error) {
	return httpraw.Mutate(c.Request, point, value)
}

func (c *Context) Rule(pluginID string) config.PluginRuleConfig {
	return c.Config.PluginRules[pluginID]
}

func payloadsForMode(rule config.PluginRuleConfig, mode string) []config.PayloadRule {
	// Mode is deliberately ignored in V2 config v15. Scan intensity is now
	// represented by explicit plugin IDs, so a selected plugin always performs
	// the same deterministic checks regardless of how it was selected.
	_ = mode
	return append([]config.PayloadRule(nil), rule.Payloads...)
}

func expandPayload(value string, replacements map[string]string) string {
	for name, replacement := range replacements {
		value = strings.ReplaceAll(value, "{{"+name+"}}", replacement)
	}
	return value
}

func severity(value string, fallback model.Severity) model.Severity {
	return model.ParseSeverity(value, fallback)
}

func confidence(value string, fallback model.Confidence) model.Confidence {
	return model.ParseConfidence(value, fallback)
}

func (c *Context) Evidence(summary string, request *httpraw.Request, response *model.Response, metrics map[string]any) model.Evidence {
	marker := evidenceMarker(metrics)
	evidence := model.Evidence{Summary: summary, Metrics: metrics, Strength: evidenceStrength(metrics)}
	if request == nil {
		request = c.Request
	}
	requestMarker := requestChangeMarker(request, c.Request)
	// Select against the actual mutated body so the returned context keeps the
	// changed field and its surrounding evidence exactly as observed.
	requestSelection := evidenceview.SelectText(string(request.Body), requestMarker)
	evidence.Request = request.RawWithBody(false, requestSelection.Text)
	evidence.RequestBase64 = base64.StdEncoding.EncodeToString(request.RawExact())
	evidence.RequestTruncated = requestSelection.Clipped
	evidence.RequestContextClipped = requestSelection.Clipped
	evidence.RequestContextStrategy = requestSelection.Strategy
	evidence.RequestContextStartLine = requestSelection.StartLine
	evidence.RequestContextEndLine = requestSelection.EndLine
	evidence.RequestContextTotalLines = requestSelection.TotalLines
	evidence.RequestContextSelectedLines = requestSelection.SelectedLines
	evidence.RequestContextAvailableBytes = int64(requestSelection.AvailableBytes)
	evidence.RequestContextSelectedBytes = int64(requestSelection.SelectedBytes)
	if response != nil {
		responseMarker := responseEvidenceMarker(response.Text(), marker, c.Baseline.Text())
		evidence.ResponseStatus = response.StatusCode
		evidence.ResponseCaptureTruncated = response.Truncated
		evidence.ResponseCapturedBytes = int64(len(response.Body))
		evidence.ResponseRawBytes = response.RawBytes
		responseEvidence, responseSelection, binaryBody := rawEvidenceResponse(*response, false, responseMarker)
		evidence.Response = responseEvidence
		if binaryBody {
			evidence.ResponseBodySHA256 = evidenceview.SHA256Hex(response.Body)
		}
		evidence.ResponseContextClipped = responseSelection.Clipped
		evidence.ResponseContextStrategy = responseSelection.Strategy
		evidence.ResponseContextStartLine = responseSelection.StartLine
		evidence.ResponseContextEndLine = responseSelection.EndLine
		evidence.ResponseContextTotalLines = responseSelection.TotalLines
		evidence.ResponseContextSelectedLines = responseSelection.SelectedLines
		evidence.ResponseContextAvailableBytes = int64(responseSelection.AvailableBytes)
		evidence.ResponseContextSelectedBytes = int64(responseSelection.SelectedBytes)
		evidence.ResponseTruncated = response.Truncated || responseSelection.Clipped
		if !binaryBody {
			evidence.ResponseExcerpt = diff.Excerpt(response.Text(), responseMarker, 800)
		}
	}
	return evidence
}

// responseEvidenceMarker keeps evidence centered on the actual response
// signal. Explicit markers are preferred, but older plugins and some passive
// findings only provide a summary/metric. For those responses, derive the
// changed segment against the representative baseline instead of silently
// falling back to an arbitrary head/tail window.
func responseEvidenceMarker(response, preferred, baseline string) string {
	preferred = strings.TrimSpace(preferred)
	if preferred != "" && strings.Contains(strings.ToLower(response), strings.ToLower(preferred)) {
		return preferred
	}
	return responseChangeMarker(response, baseline)
}

func responseChangeMarker(response, baseline string) string {
	response = normalizeEvidenceText(response)
	baseline = normalizeEvidenceText(baseline)
	if response == "" || baseline == "" || response == baseline {
		return ""
	}
	prefix := 0
	for prefix < len(response) && prefix < len(baseline) && response[prefix] == baseline[prefix] {
		prefix++
	}
	if prefix == len(response) && prefix == len(baseline) {
		return ""
	}
	suffix := 0
	for suffix < len(response)-prefix && suffix < len(baseline)-prefix &&
		response[len(response)-1-suffix] == baseline[len(baseline)-1-suffix] {
		suffix++
	}
	end := len(response) - suffix
	if end <= prefix {
		return ""
	}
	changed := strings.TrimSpace(response[prefix:end])
	if changed == "" {
		return ""
	}
	if len(changed) > 512 {
		changed = changed[:512]
	}
	return strings.ToValidUTF8(changed, "�")
}

func normalizeEvidenceText(text string) string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	return strings.ReplaceAll(text, "\r", "\n")
}

// rawEvidenceResponse keeps the legacy redact argument for in-package callers;
// evidence serialization intentionally ignores it and always preserves values.
func rawEvidenceResponse(response model.Response, _ bool, marker string) (string, evidenceview.Selection, bool) {
	var builder strings.Builder
	fmt.Fprintf(&builder, "HTTP/1.1 %d %s\r\n", response.StatusCode, http.StatusText(response.StatusCode))
	names := make([]string, 0, len(response.Headers))
	for name := range response.Headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		values := response.HeaderAll(name)
		for _, value := range values {
			fmt.Fprintf(&builder, "%s: %s\r\n", name, value)
		}
	}
	builder.WriteString("\r\n")
	if evidenceview.IsBinary(response.Header("content-type"), response.Body) {
		captured := int64(len(response.Body))
		rawBytes := "unknown"
		if response.RawBytes > 0 {
			rawBytes = fmt.Sprintf("%d", response.RawBytes)
		}
		body := fmt.Sprintf("[binary body; content_type=%s captured_bytes=%d raw_bytes=%s sha256=%s capture_complete=%t]",
			response.Header("content-type"), captured, rawBytes, evidenceview.SHA256Hex(response.Body), !response.Truncated)
		builder.WriteString(body)
		selection := evidenceview.Selection{Strategy: "binary", Clipped: captured > 0, AvailableBytes: len(response.Body), SelectedBytes: len(body)}
		return builder.String(), selection, true
	}
	selection := evidenceview.SelectText(response.Text(), marker)
	body := selection.Text
	if selection.Clipped || response.Truncated {
		body += "\n...[evidence context clipped; response_capture_truncated=" + fmt.Sprint(response.Truncated) + "]"
	}
	builder.WriteString(body)
	return builder.String(), selection, false
}

func requestChangeMarker(request, baseline *httpraw.Request) string {
	if request == nil || baseline == nil {
		return ""
	}
	current := string(request.Body)
	original := string(baseline.Body)
	prefix := 0
	for prefix < len(current) && prefix < len(original) && current[prefix] == original[prefix] {
		prefix++
	}
	if prefix == len(current) && prefix == len(original) {
		return ""
	}
	suffix := 0
	for suffix < len(current)-prefix && suffix < len(original)-prefix && current[len(current)-1-suffix] == original[len(original)-1-suffix] {
		suffix++
	}
	end := len(current) - suffix
	if end <= prefix {
		return ""
	}
	changed := current[prefix:end]
	if len(changed) > 512 {
		changed = changed[:512]
	}
	return strings.ToValidUTF8(changed, "�")
}

func evidenceMarker(metrics map[string]any) string {
	for _, key := range []string{"match", "marker", "token", "expected", "canary", "output", "payload"} {
		if value, ok := metrics[key].(string); ok && strings.TrimSpace(value) != "" && len(value) <= 512 {
			return value
		}
	}
	return ""
}

// Evidence strength is a stable machine-readable ladder used by V2 clients:
// L5 out-of-band or repeated execution, L4 paired/repeated confirmation,
// L3 unique error/signature, L2 differential heuristic, L1 passive indicator.
func evidenceStrength(metrics map[string]any) string {
	if metrics == nil {
		return "L1"
	}
	// New and migrated plugins should declare the semantic evidence strength
	// explicitly. Metrics-based inference remains only as a compatibility
	// fallback for older rule implementations.
	if declared, ok := metrics["evidence_strength"].(string); ok {
		switch strings.ToUpper(strings.TrimSpace(declared)) {
		case "L1", "L2", "L3", "L4", "L5":
			return strings.ToUpper(strings.TrimSpace(declared))
		}
	}
	for _, key := range []string{"callback", "oast", "command_executed", "confirmed_execution"} {
		if value, ok := metrics[key].(bool); ok && value {
			return "L5"
		}
	}
	for _, key := range []string{"repeat_confirmed", "paired_confirmed", "control_similarity", "true_similarity", "false_similarity"} {
		if _, ok := metrics[key]; ok {
			return "L4"
		}
	}
	for _, key := range []string{"match", "pattern", "expected", "database_error"} {
		if _, ok := metrics[key]; ok {
			return "L3"
		}
	}
	if _, ok := metrics["similarity"]; ok {
		return "L2"
	}
	return "L1"
}

func waitCallbackBatch(ctx context.Context, registry *callback.Registry, tokens []string, timeout time.Duration) map[string]bool {
	return registry.WaitBatch(ctx, tokens, timeout)
}

func Finding(meta model.PluginMeta, title string, severity model.Severity, confidence model.Confidence, affected, description, remediation string, evidence []model.Evidence, references ...string) model.Finding {
	return model.Finding{
		ID: randomID("finding"), PluginID: meta.ID, Title: title, Severity: severity,
		Confidence: confidence, Affected: affected, Description: description,
		Remediation: remediation, Evidence: evidence, References: references, DetectedAt: time.Now().UTC(),
	}
}

func StandardMeta(id, name, description, risk string, defaultEnabled bool) model.PluginMeta {
	return model.PluginMeta{ID: id, Name: name, Description: description, Risk: risk, DefaultEnabled: defaultEnabled, Modes: []string{"passive", "normal", "standard", "deep"}, Version: "2.4.0"}
}

func PassiveMeta(id, name, description string) model.PluginMeta {
	return model.PluginMeta{ID: id, Name: name, Description: description, Risk: "passive", DefaultEnabled: true, Modes: []string{"passive", "normal", "standard", "deep"}, Version: "2.4.0"}
}

var registry = []Plugin{
	Unauthorized{}, SQLInjection{}, SQLInjectionExtended{}, SQLInjectionTiming{}, SQLOrderBy{}, SQLLimit{},
	XXE{}, XXEExtended{}, FileRead{}, FileReadEncoded{}, FileUpload{}, FileUploadExecution{}, SensitiveData{},
	CORS{}, ReflectedXSS{}, SSRF{}, OpenRedirect{}, CRLFInjection{},
	SSTI{}, SpringActuator{}, SecurityHeaders{}, JWTWeak{}, IDOR{},
	CommandInjection{}, CommandInjectionOAST{}, CommandInjectionTiming{}, CSRF{}, APIExposure{},
	ErrorDisclosure{}, ErrorDisclosureExtended{}, NoSQLInjection{},
	LDAPInjection{}, XPathInjection{}, JavaDeserialization{}, MethodOverride{},
	MassAssignment{}, MassAssignmentExtended{}, MyBatisDynamicSQL{}, PathNormalization{}, ParameterConfusion{},
	JSONPolymorphic{}, GraphQLSecurity{}, GraphQLAliasAbuse{}, SMSAbuse{},
	Shiro{}, JavaExpression{}, JavaExpressionExtended{}, JNDIInjection{}, HostHeaderInjection{},
	JWTActive{}, ProxyTrustBypass{}, HTTPTrace{},
}

var normalActivePluginIDs = map[string]bool{
	"sqli": true, "sqli_extended": true, "file_upload": true,
	"file_read": true, "reflected_xss": true, "unauthorized": true,
	"xxe": true, "sms_abuse": true, "sensitive_data": true,
}

func PresetIDs(name string) ([]string, error) {
	return PresetIDsWithNormal(name, nil)
}

// PresetIDsWithNormal expands a preset, allowing persistent configuration to
// define the active plugins included by the normal preset.
func PresetIDsWithNormal(name string, normalPlugins []string) ([]string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	normal := normalActivePluginIDs
	if normalPlugins != nil {
		normal = make(map[string]bool, len(normalPlugins))
		for _, id := range normalPlugins {
			normal[strings.TrimSpace(id)] = true
		}
	}
	var result []string
	for _, item := range All() {
		meta := item.Meta()
		switch name {
		case "passive":
			if meta.Risk == "passive" {
				result = append(result, meta.ID)
			}
		case "normal":
			if normal[meta.ID] {
				result = append(result, meta.ID)
			}
		case "deep":
			result = append(result, meta.ID)
		default:
			return nil, fmt.Errorf("未知扫描预设: %s", name)
		}
	}
	return result, nil
}

func All() []Plugin {
	result := append([]Plugin(nil), registry...)
	sort.Slice(result, func(i, j int) bool { return result[i].Meta().ID < result[j].Meta().ID })
	return result
}

func Metadata() []model.PluginMeta {
	plugins := All()
	result := make([]model.PluginMeta, 0, len(plugins))
	for _, item := range plugins {
		result = append(result, item.Meta())
	}
	return result
}

func Select(ids []string, mode string) ([]Plugin, error) {
	// mode is accepted for V1/V1.4 API compatibility only. V2.0 selection is
	// entirely defined by plugin IDs (or a preset expanded into plugin IDs).
	_ = mode
	selected := make(map[string]bool)
	for _, id := range ids {
		selected[id] = true
	}
	allSelected := selected["all"]
	var result []Plugin
	for _, item := range All() {
		meta := item.Meta()
		if allSelected || selected[meta.ID] {
			result = append(result, item)
			delete(selected, meta.ID)
		}
	}
	delete(selected, "all")
	if len(selected) > 0 {
		unknown := make([]string, 0, len(selected))
		for id := range selected {
			unknown = append(unknown, id)
		}
		sort.Strings(unknown)
		return nil, fmt.Errorf("未知漏洞类型: %s", strings.Join(unknown, ", "))
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("没有选择可运行的插件")
	}
	return result, nil
}

func randomID(prefix string) string {
	raw := make([]byte, 12)
	_, _ = rand.Read(raw)
	return prefix + "_" + hex.EncodeToString(raw)
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
