package model

import (
	"fmt"
	"strings"
	"time"
)

type Severity string

const (
	SeverityInfo     Severity = "提示"
	SeverityLow      Severity = "低危"
	SeverityMedium   Severity = "中危"
	SeverityHigh     Severity = "高危"
	SeverityCritical Severity = "严重"
)

type Confidence string

const (
	ConfidenceTentative Confidence = "待确认"
	ConfidenceFirm      Confidence = "较确定"
	ConfidenceCertain   Confidence = "已确认"
)

func ParseSeverity(value string, fallback Severity) Severity {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "info", "提示":
		return SeverityInfo
	case "low", "低危":
		return SeverityLow
	case "medium", "中危":
		return SeverityMedium
	case "high", "高危":
		return SeverityHigh
	case "critical", "严重":
		return SeverityCritical
	default:
		return fallback
	}
}

func ParseConfidence(value string, fallback Confidence) Confidence {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "tentative", "待确认":
		return ConfidenceTentative
	case "firm", "较确定":
		return ConfidenceFirm
	case "certain", "已确认":
		return ConfidenceCertain
	default:
		return fallback
	}
}

type Evidence struct {
	Summary           string         `json:"summary"`
	Strength          string         `json:"strength,omitempty"`
	Request           string         `json:"request,omitempty"`
	Response          string         `json:"response,omitempty"`
	ResponseStatus    int            `json:"response_status,omitempty"`
	ResponseExcerpt   string         `json:"response_excerpt,omitempty"`
	ResponseTruncated bool           `json:"response_truncated,omitempty"`
	Metrics           map[string]any `json:"metrics,omitempty"`
}

type Finding struct {
	ID          string     `json:"id"`
	PluginID    string     `json:"plugin_id"`
	Title       string     `json:"title"`
	Severity    Severity   `json:"severity"`
	Confidence  Confidence `json:"confidence"`
	Affected    string     `json:"affected"`
	Description string     `json:"description"`
	Remediation string     `json:"remediation"`
	Evidence    []Evidence `json:"evidence"`
	References  []string   `json:"references,omitempty"`
	DetectedAt  time.Time  `json:"detected_at"`
	Category    string     `json:"category"`
	Score       int        `json:"score"`
	Correlation string     `json:"correlation_id,omitempty"`
}

type PluginCoverage struct {
	Name              string `json:"name"`
	Status            string `json:"status"`
	Applicable        bool   `json:"applicable"`
	Reason            string `json:"reason,omitempty"`
	PointsTotal       int    `json:"points_total"`
	PointsCompleted   int    `json:"points_completed"`
	EstimatedRequests int    `json:"estimated_requests"`
	RequestBudget     int    `json:"request_budget"`
	RequestsSent      int    `json:"requests_sent"`
	AdaptivePruned    int    `json:"adaptive_pruned,omitempty"`
	MutationFailed    int    `json:"mutation_failed,omitempty"`
	BudgetSkipped     int    `json:"budget_skipped,omitempty"`
}

type Coverage struct {
	Complete         bool                      `json:"complete"`
	DiscoveredPoints int                       `json:"discovered_points"`
	PlannedRequests  int                       `json:"planned_requests"`
	RequestBudget    int                       `json:"request_budget"`
	RequestsSent     int                       `json:"requests_sent"`
	PluginsCompleted int                       `json:"plugins_completed"`
	PluginsPartial   int                       `json:"plugins_partial"`
	PluginsFailed    int                       `json:"plugins_failed"`
	PluginsSkipped   int                       `json:"plugins_skipped"`
	Plugins          map[string]PluginCoverage `json:"plugins"`
}

type ScanPlan struct {
	Mode                 string                    `json:"mode"`
	Method               string                    `json:"method"`
	URL                  string                    `json:"url"`
	DiscoveredPoints     int                       `json:"discovered_points"`
	EstimatedRequests    int                       `json:"estimated_requests"`
	RequestBudget        int                       `json:"request_budget"`
	EstimatedSeconds     int                       `json:"estimated_seconds"`
	CompleteWithinBudget bool                      `json:"complete_within_budget"`
	Plugins              map[string]PluginCoverage `json:"plugins"`
}

type FindingCorrelation struct {
	ID       string   `json:"id"`
	Affected string   `json:"affected"`
	Family   string   `json:"family"`
	Findings []string `json:"finding_ids"`
	Summary  string   `json:"summary"`
}

type PluginMeta struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Risk           string   `json:"risk"`
	DefaultEnabled bool     `json:"default_enabled"`
	Modes          []string `json:"modes"`
	Version        string   `json:"version"`
}

type ScanInput struct {
	HTTP              string            `json:"http"`
	ScanType          []string          `json:"scan_type"`
	HTTPRequest       string            `json:"http_request,omitempty"`
	Plugins           []string          `json:"plugins,omitempty"`
	Mode              string            `json:"mode,omitempty"`
	ScanMode          string            `json:"scan_mode,omitempty"`
	Scheme            string            `json:"scheme,omitempty"`
	Host              map[string]string `json:"host,omitempty"`
	ClientTLS         *ClientTLSInput   `json:"client_tls,omitempty"`
	ClientTLSFile     string            `json:"client_tls_file,omitempty"`
	ClientTLSPassword string            `json:"client_tls_password,omitempty"`
}

// ClientTLSInput carries one request-scoped mutual-TLS identity. Certificate
// material and passwords are never persisted in Config or exposed by ScanView.
// PEM expects the certificate chain and private key in the same file.
type ClientTLSInput struct {
	Format     string `json:"format"`
	DataBase64 string `json:"data_base64"`
	File       string `json:"file,omitempty"`
	Password   string `json:"password,omitempty"`
	Filename   string `json:"filename,omitempty"`
}

func (s ScanInput) ResolveScheme(defaultScheme string) (scheme string, auto bool, err error) {
	requested := strings.ToLower(strings.TrimSpace(s.Scheme))
	switch requested {
	case "", "auto":
		// Auto always starts with HTTP and lets the transport retry HTTPS on
		// connection/protocol failure. The retained parameter keeps source/API
		// compatibility with earlier versions; persistent default_scheme is no
		// longer used for automatic requests.
		_ = defaultScheme
		return "http", true, nil
	case "http", "https":
		return requested, false, nil
	default:
		return "", false, fmt.Errorf("scheme 必须是 auto、http 或 https")
	}
}

func (s ScanInput) RawHTTP() string {
	if s.HTTP != "" {
		return s.HTTP
	}
	return s.HTTPRequest
}

func (s ScanInput) SelectedPlugins() []string {
	if len(s.ScanType) > 0 {
		return s.ScanType
	}
	return s.Plugins
}

func (s ScanInput) SelectedMode() string {
	if s.Mode != "" {
		return s.Mode
	}
	if s.ScanMode != "" {
		return s.ScanMode
	}
	return ""
}

type Response struct {
	StatusCode   int                 `json:"status_code"`
	Headers      map[string]string   `json:"headers"`
	HeaderValues map[string][]string `json:"header_values,omitempty"`
	Body         []byte              `json:"-"`
	Elapsed      time.Duration       `json:"-"`
	URL          string              `json:"url"`
	Charset      string              `json:"charset,omitempty"`
	RawBytes     int64               `json:"raw_bytes,omitempty"`
	Truncated    bool                `json:"truncated,omitempty"`
}

func (r Response) Text() string { return string(r.Body) }

// Header returns the compatibility single-value representation. Callers that
// need exact repeated fields (especially Set-Cookie) should use HeaderAll.
func (r Response) Header(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	if value, ok := r.Headers[lower]; ok {
		return value
	}
	if values := r.HeaderValues[lower]; len(values) > 0 {
		return strings.Join(values, ", ")
	}
	return ""
}

func (r Response) HeaderAll(name string) []string {
	lower := strings.ToLower(strings.TrimSpace(name))
	if values := r.HeaderValues[lower]; len(values) > 0 {
		return append([]string(nil), values...)
	}
	if value, ok := r.Headers[lower]; ok {
		return []string{value}
	}
	return nil
}

type PluginProgress struct {
	Name           string `json:"name"`
	Completed      int    `json:"completed"`
	Total          int    `json:"total"`
	Status         string `json:"status"`
	RequestsSent   int    `json:"requests_sent,omitempty"`
	AdaptivePruned int    `json:"adaptive_pruned,omitempty"`
	MutationFailed int    `json:"mutation_failed,omitempty"`
	BudgetSkipped  int    `json:"budget_skipped,omitempty"`
}

type Progress struct {
	Phase            string                    `json:"phase"`
	Plugin           string                    `json:"plugin,omitempty"`
	CompletedChecks  int                       `json:"completed_checks"`
	TotalChecks      int                       `json:"total_checks"`
	PlannedRequests  int                       `json:"planned_requests"`
	ResolvedRequests int                       `json:"resolved_requests"`
	RequestsSkipped  int                       `json:"requests_skipped"`
	AdaptivePruned   int                       `json:"adaptive_pruned,omitempty"`
	MutationFailures int                       `json:"mutation_failures,omitempty"`
	BudgetSkipped    int                       `json:"budget_skipped,omitempty"`
	RequestsSent     int                       `json:"requests_sent"`
	NetworkErrors    int                       `json:"network_errors"`
	Percent          int                       `json:"percent"`
	Plugins          map[string]PluginProgress `json:"plugins"`
}

type ScanView struct {
	ScanID        string               `json:"scan_id"`
	Status        string               `json:"status"`
	CreatedAt     time.Time            `json:"created_at"`
	StartedAt     *time.Time           `json:"started_at,omitempty"`
	FinishedAt    *time.Time           `json:"finished_at,omitempty"`
	ElapsedMS     int64                `json:"elapsed_ms"`
	Progress      Progress             `json:"progress"`
	FindingsCount int                  `json:"findings_count"`
	Error         string               `json:"error,omitempty"`
	Warnings      []string             `json:"warnings"`
	Coverage      Coverage             `json:"coverage"`
	Correlations  []FindingCorrelation `json:"correlations,omitempty"`
}
