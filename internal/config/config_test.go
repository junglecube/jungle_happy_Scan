package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestDefaultDisablesTLSVerificationForIntranetTargets(t *testing.T) {
	if Default().VerifyTLS {
		t.Fatal("intranet default must not require public CA trust")
	}
}

func TestDefaultLinuxFileReadFingerprints(t *testing.T) {
	samples := map[string]string{
		"passwd 绝对路径":       "root:x:0:0:root:/root:/bin/sh\n",
		"hosts 绝对路径":        "127.0.0.1 localhost\n::1 localhost ip6-localhost\n",
		"proc/version 绝对路径": "Linux version 6.8.0-test (builder@gcc) #1 SMP\n",
		"os-release 绝对路径":   "NAME=\"Test Linux\"\nVERSION=\"1\"\nID=\"test-linux\"\n",
	}
	for _, payload := range Default().PluginRules["file_read"].Payloads {
		sample, ok := samples[payload.Name]
		if !ok {
			continue
		}
		expression, err := regexp.Compile(payload.Expected)
		if err != nil || !expression.MatchString(sample) {
			t.Fatalf("file-read fingerprint %q does not match its Linux sample: %v", payload.Name, err)
		}
		delete(samples, payload.Name)
	}
	if len(samples) != 0 {
		t.Fatalf("missing default file-read fingerprints: %#v", samples)
	}
}

func TestV19UpgradeRestoresJSPXUploadProbe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := Default()
	cfg.ConfigVersion = 18
	upload := cfg.PluginRules["file_upload"]
	filtered := upload.Payloads[:0]
	for _, payload := range upload.Payloads {
		if !strings.EqualFold(filepath.Ext(payload.Payload), ".jspx") {
			filtered = append(filtered, payload)
		}
	}
	upload.Payloads = filtered
	cfg.PluginRules["file_upload"] = upload
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, payload := range store.Get().PluginRules["file_upload"].Payloads {
		if strings.EqualFold(filepath.Ext(payload.Payload), ".jspx") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("V19 migration did not restore the default JSPX upload probe")
	}
}

func TestV30UpgradeRestoresExactMySQLAndSelectTimingPair(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := Default()
	cfg.ConfigVersion = 29
	cfg.NormalPlugins = []string{"sqli_timing"}
	timing := cfg.PluginRules["sqli_timing"]
	filtered := timing.Payloads[:0]
	for _, payload := range timing.Payloads {
		if payload.Group != "mysql-sleep-and-select-exact-replace" {
			filtered = append(filtered, payload)
		}
	}
	timing.Payloads = filtered
	cfg.PluginRules["sqli_timing"] = timing
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	upgraded := store.Get()
	if upgraded.ConfigVersion != currentConfigVersion || len(upgraded.NormalPlugins) != 1 || upgraded.NormalPlugins[0] != "sqli_timing" {
		t.Fatalf("V30 upgrade changed configured normal plugins: %#v", upgraded.NormalPlugins)
	}
	found := 0
	for _, payload := range upgraded.PluginRules["sqli_timing"].Payloads {
		if payload.Group == "mysql-sleep-and-select-exact-replace" {
			found++
		}
	}
	if found != 2 {
		t.Fatalf("V30 migration did not restore exact MySQL AND SELECT timing pair: %d", found)
	}
}

func TestV30UpgradeReplacesOnlyHistoricalNormalPreset(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := Default()
	cfg.ConfigVersion = 29
	cfg.NormalPlugins = []string{"reflected_xss", "file_read", "file_upload", "error_disclosure", "unauthorized", "cors", "sqli", "xxe", "sms_abuse"}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	want := Default().NormalPlugins
	if got := store.Get().NormalPlugins; !slices.Equal(got, want) {
		t.Fatalf("historical normal preset was not upgraded: got=%#v want=%#v", got, want)
	}
}

func TestStoreCreatesAndAtomicallyPersistsConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := store.Get()
	cfg.DefaultScheme = "http"
	cfg.MaxConcurrency = 17
	fileRule := cfg.PluginRules["file_read"]
	fileRule.Payloads = append(fileRule.Payloads, PayloadRule{Name: "自定义文件", Payload: "/custom/secret", Expected: "CUSTOM_SECRET"})
	cfg.PluginRules["file_read"] = fileRule
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	reloaded, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Get().MaxConcurrency != 17 || reloaded.Get().DefaultScheme != "http" || len(reloaded.Get().PluginRules["file_read"].Payloads) != len(fileRule.Payloads) {
		t.Fatalf("config was not persisted: %#v", reloaded.Get())
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("unexpected config permissions %o", info.Mode().Perm())
	}
}

func TestOpenUpgradesSQLRulesWithoutLosingCustomPayload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := Default()
	cfg.ConfigVersion = 3
	cfg.CommandParameterNames = []string{"cmd", "command", "exec"}
	cfg.APIExposurePaths = append(cfg.APIExposurePaths, "/graphql")
	cfg.PluginRules["file_read"] = PluginRuleConfig{
		ParameterNames: []string{"filepath"},
		Payloads: []PayloadRule{
			{Name: "Linux 目录穿越", Payload: "../../../../../../etc/passwd", Expected: `(?m)^root:x?:0:0:`},
			{Name: "管理员自定义文件", Payload: "/opt/app/custom.secret", Expected: "CUSTOM_SECRET"},
		},
	}
	fileUpload := cfg.PluginRules["file_upload"]
	fileUpload.Payloads[1] = PayloadRule{Name: "EXE 文件", Payload: "legacy.exe", Mime: "application/octet-stream"}
	cfg.PluginRules["file_upload"] = fileUpload
	errorRule := cfg.PluginRules["error_disclosure"]
	errorRule.Patterns = append(errorRule.Patterns, DetectionRule{Name: "服务端绝对路径", Pattern: `[A-Za-z]:\\temp\\app\.jar`, Severity: "medium", Confidence: "firm"})
	cfg.PluginRules["error_disclosure"] = errorRule
	for _, pluginID := range []string{"error_disclosure", "nosql_injection", "ldap_injection", "xpath_injection", "java_deserialization", "method_override", "mass_assignment", "mybatis_dynamic_sql", "path_normalization", "parameter_confusion", "json_polymorphic", "graphql_security"} {
		delete(cfg.PluginRules, pluginID)
	}
	cfg.PluginRules["json_polymorphic"] = PluginRuleConfig{
		Patterns: []DetectionRule{
			{Name: "Fastjson AutoType 解析", Pattern: `safeMode not support autoType`, Severity: "high", Confidence: "certain"},
			{Name: "管理员自定义多态规则", Pattern: `CUSTOM_POLYMORPHIC_MARKER`, Severity: "medium", Confidence: "firm"},
		},
	}
	orderRule := cfg.PluginRules["sqli_order_by"]
	orderRule.Payloads = append(orderRule.Payloads,
		PayloadRule{Name: "MySQL ORDER BY 条件正常分支", Kind: "conditional_control", Group: "mysql-order-exp", Payload: "IF(731=731,{{value}},EXP(720))"},
		PayloadRule{Name: "MySQL ORDER BY 条件溢出分支", Kind: "conditional_error", Group: "mysql-order-exp", Payload: "IF(731=732,{{value}},EXP(720))"},
	)
	cfg.PluginRules["sqli_order_by"] = orderRule
	rule := cfg.PluginRules["sqli"]
	filtered := rule.Payloads[:0]
	for _, payload := range rule.Payloads {
		if payload.Group != "postgres-pg-sleep-and" && payload.Group != "mysql-sleep-and" {
			filtered = append(filtered, payload)
		}
	}
	rule.Payloads = append(filtered,
		PayloadRule{Name: "SQL Server 旧规则", Kind: "time_delay", Group: "mssql-waitfor", Payload: "{{value}}; WAITFOR DELAY '00:00:02'-- "},
		PayloadRule{Name: "管理员自定义真条件", Kind: "boolean_true", Group: "custom", Payload: "{{value}} AND 1=1"},
		PayloadRule{Name: "管理员自定义假条件", Kind: "boolean_false", Group: "custom", Payload: "{{value}} AND 1=2"},
	)
	rule.Patterns = append(rule.Patterns, DetectionRule{Name: "SQL Server/JDBC 异常", Pattern: `SQLServerException`, Severity: "high", Confidence: "certain"})
	cfg.PluginRules["sqli"] = rule
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got := store.Get()
	if got.ConfigVersion != currentConfigVersion {
		t.Fatalf("config was not upgraded: %d", got.ConfigVersion)
	}
	if got.CallbackListen != "0.0.0.0:61166" || got.CallbackBaseURL == "" {
		t.Fatalf("upgraded config missing callback listener defaults: listen=%q base=%q", got.CallbackListen, got.CallbackBaseURL)
	}
	if got.CallbackMaxConnections != 128 {
		t.Fatalf("upgraded config missing callback connection limit: %d", got.CallbackMaxConnections)
	}
	if !containsStringFold(got.PluginRules["ssrf"].ParameterNames, "domain") {
		t.Fatalf("upgraded config missing SSRF domain candidate: %#v", got.PluginRules["ssrf"].ParameterNames)
	}
	if !containsStringFold(got.CommandParameterNames, "executable") {
		t.Fatalf("upgraded config missing V2.3 Java command contexts: %#v", got.CommandParameterNames)
	}
	for _, payload := range got.PluginRules["sqli_order_by"].Payloads {
		if payload.Group == "mysql-order-exp" || payload.Group == "mysql-order-sleep" {
			t.Fatalf("legacy ORDER BY context remained: %#v", payload)
		}
	}
	groups := map[string]bool{}
	for _, payload := range got.PluginRules["sqli"].Payloads {
		groups[payload.Group] = true
	}
	for _, expected := range []string{"custom", "quote", "quote-concat-empty", "numeric", "and-string"} {
		if !groups[expected] {
			t.Fatalf("upgraded SQL rules missing group %q: %#v", expected, groups)
		}
	}
	if !groups["postgres-exp-string"] || len(got.SQLiErrorPatterns) == 0 {
		t.Fatalf("upgraded config missing V2.1 conditional SQL rules or error patterns: groups=%#v patterns=%#v", groups, got.SQLiErrorPatterns)
	}
	timingGroups := map[string]bool{}
	for _, payload := range got.PluginRules["sqli_timing"].Payloads {
		timingGroups[payload.Group] = true
		if payload.Mode != "" {
			t.Fatalf("migrated SQL timing payload still depends on mode: %#v", payload)
		}
	}
	for _, expected := range []string{"postgres-pg-sleep-and", "gaussdb-pg-sleep-and", "mysql-sleep-and", "mysql-sleep-double-quote"} {
		if !timingGroups[expected] {
			t.Fatalf("upgraded SQL timing rules missing group %q: %#v", expected, timingGroups)
		}
	}
	extendedGroups := map[string]bool{}
	for _, payload := range got.PluginRules["sqli_extended"].Payloads {
		extendedGroups[payload.Group] = true
	}
	if !extendedGroups["double-quote-string"] {
		t.Fatalf("upgraded SQL extended rules missing double-quote Boolean pair: %#v", extendedGroups)
	}
	for group := range groups {
		if len(group) >= 6 && group[:6] == "mssql-" {
			t.Fatalf("legacy SQL Server payload was not removed: %#v", groups)
		}
	}
	for _, pattern := range got.PluginRules["sqli"].Patterns {
		if pattern.Name == "SQL Server/JDBC 异常" {
			t.Fatalf("legacy SQL Server pattern was not removed: %#v", pattern)
		}
	}
	for _, pluginID := range []string{"error_disclosure", "nosql_injection", "ldap_injection", "xpath_injection", "java_deserialization", "method_override", "mass_assignment", "mybatis_dynamic_sql", "json_polymorphic", "graphql_security", "sms_abuse", "sqli_extended", "sqli_timing", "sqli_order_by", "sqli_limit", "xxe_extended", "file_read_encoded", "file_upload_execution", "command_injection_oast", "command_injection_timing", "java_expression_extended", "mass_assignment_extended", "graphql_alias_abuse", "error_disclosure_extended"} {
		rule := got.PluginRules[pluginID]
		if len(rule.Payloads) == 0 {
			t.Fatalf("upgraded config missing default rules for %s", pluginID)
		}
	}
	for _, pluginID := range []string{"command_injection", "command_injection_oast", "command_injection_timing"} {
		rule := got.PluginRules[pluginID]
		if !containsStringFold(rule.ParameterNames, "backuppath") {
			t.Fatalf("upgraded config missing backuppath candidate for %s: %#v", pluginID, rule.ParameterNames)
		}
	}
	hasPayload := func(name string) bool {
		for _, payload := range got.PluginRules["command_injection_oast"].Payloads {
			if payload.Name == name {
				return true
			}
		}
		return false
	}
	if !hasPayload("反引号 curl 离线回连") || !hasPayload("美元括号 curl 离线回连") {
		t.Fatalf("upgraded config missing command substitution callbacks: %#v", got.PluginRules["command_injection_oast"].Payloads)
	}
	if len(got.PluginRules["sms_abuse"].Payloads) < 30 {
		t.Fatalf("upgraded SMS rules must provide 30 spray numbers, got %d", len(got.PluginRules["sms_abuse"].Payloads))
	}
	if !containsStringFold(got.PluginRules["sms_abuse"].URLKeywords, "send") {
		t.Fatalf("upgraded SMS rules must require the default send URL keyword: %#v", got.PluginRules["sms_abuse"].URLKeywords)
	}
	foundWeChatSecret := false
	for _, pattern := range got.PluginRules["sensitive_data"].Patterns {
		if pattern.Name == "微信小程序 AppSecret" {
			foundWeChatSecret = true
			break
		}
	}
	if !foundWeChatSecret {
		t.Fatal("upgraded sensitive-data rules missing WeChat AppSecret pattern")
	}
	for _, targetPath := range got.APIExposurePaths {
		if targetPath == "/graphql" {
			t.Fatal("legacy GraphQL path remained in OpenAPI exposure paths")
		}
	}
	uploadExtensions := make(map[string]bool)
	for _, payload := range got.PluginRules["file_upload"].Payloads {
		uploadExtensions[strings.ToLower(filepath.Ext(payload.Payload))] = true
	}
	for _, expected := range []string{".jsp", ".jspx", ".php", ".exe", ".sh", ".html", ".py"} {
		if !uploadExtensions[expected] {
			t.Fatalf("upgraded file-upload rules missing %q: %#v", expected, uploadExtensions)
		}
	}
	for _, pattern := range got.PluginRules["error_disclosure"].Patterns {
		if pattern.Name == "服务端绝对路径" {
			t.Fatalf("legacy Windows path pattern remained: %#v", pattern)
		}
	}
	fileReadNames := make(map[string]bool)
	for _, payload := range got.PluginRules["file_read"].Payloads {
		fileReadNames[payload.Name] = true
	}
	for _, expected := range []string{"管理员自定义文件", "passwd 目录穿越", "hosts 绝对路径", "proc/version 绝对路径", "os-release 绝对路径"} {
		if !fileReadNames[expected] {
			t.Fatalf("upgraded file-read rules missing %q: %#v", expected, fileReadNames)
		}
	}
	if fileReadNames["Linux 目录穿越"] {
		t.Fatalf("legacy duplicate file-read rule remained: %#v", fileReadNames)
	}
	polymorphicNames := make(map[string]bool)
	for _, pattern := range got.PluginRules["json_polymorphic"].Patterns {
		polymorphicNames[pattern.Name] = true
	}
	for _, expected := range []string{"Fastjson SafeMode 已开启", "Fastjson SafeMode 未开启特征"} {
		if !polymorphicNames[expected] {
			t.Fatalf("upgraded polymorphic rules missing %q: %#v", expected, polymorphicNames)
		}
	}
	if polymorphicNames["Fastjson AutoType 解析"] || polymorphicNames["管理员自定义多态规则"] ||
		polymorphicNames["JSON 多态安全策略阻断"] {
		t.Fatalf("legacy polymorphic rules remained after V2.3 replacement: %#v", polymorphicNames)
	}
}

func containsStringFold(values []string, wanted string) bool {
	for _, value := range values {
		if strings.EqualFold(value, wanted) {
			return true
		}
	}
	return false
}

func TestConfigRejectsInvalidRegex(t *testing.T) {
	cfg := Default()
	cfg.SuccessPatterns = []string{"["}
	if cfg.Validate() == nil {
		t.Fatal("expected invalid regex error")
	}
}

func TestConfigRejectsInvalidSQLiErrorRegex(t *testing.T) {
	cfg := Default()
	cfg.SQLiErrorPatterns = []string{`ORA-\d{5}`, `[`}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "sqli_error_patterns") {
		t.Fatalf("expected named SQLi error regex validation failure, got %v", err)
	}
}

func TestV24SQLRuleLint(t *testing.T) {
	t.Run("default-rule-pack", func(t *testing.T) {
		cfg := Default()
		if err := cfg.Validate(); err != nil {
			t.Fatalf("V2.4 default SQL rules must pass lint: %v", err)
		}
		if cfg.SQLiErrorConfidence != "firm" {
			t.Fatalf("compact SQL error patterns must default to firm, got %q", cfg.SQLiErrorConfidence)
		}
		orderGroups, limitGroups := map[string]bool{}, map[string]bool{}
		for _, payload := range cfg.PluginRules["sqli_order_by"].Payloads {
			orderGroups[payload.Group] = true
		}
		for _, payload := range cfg.PluginRules["sqli_limit"].Payloads {
			limitGroups[payload.Group] = true
		}
		if !orderGroups["postgres-gauss-order-field-cast"] ||
			!orderGroups["postgres-gauss-order-direction-cast"] ||
			!limitGroups["postgres-gauss-limit-cast"] {
			t.Fatalf("PostgreSQL/GaussDB clause pairs missing: order=%#v limit=%#v", orderGroups, limitGroups)
		}
		for _, payload := range cfg.PluginRules["mybatis_dynamic_sql"].Payloads {
			if payload.Mode == "deep" || strings.Contains(payload.Name, "深度变体") {
				t.Fatalf("legacy MyBatis deep payload leaked into deterministic rule pack: %#v", payload)
			}
		}
	})

	testCases := []struct {
		name   string
		mutate func(*Config)
		match  string
	}{
		{
			name: "missing-pair",
			mutate: func(cfg *Config) {
				rule := cfg.PluginRules["sqli_limit"]
				rule.Payloads = rule.Payloads[:1]
				cfg.PluginRules["sqli_limit"] = rule
			},
			match: "缺少配对",
		},
		{
			name: "unbalanced-duplicate-kind-in-group",
			mutate: func(cfg *Config) {
				rule := cfg.PluginRules["sqli_limit"]
				rule.Payloads = append(rule.Payloads, rule.Payloads[0])
				cfg.PluginRules["sqli_limit"] = rule
			},
			match: "数量为",
		},
		{
			name: "missing-value-placeholder",
			mutate: func(cfg *Config) {
				rule := cfg.PluginRules["sqli_order_by"]
				rule.Payloads[0].Payload = "IF(731=731,id,EXP(720))"
				cfg.PluginRules["sqli_order_by"] = rule
			},
			match: "缺少 {{value}}",
		},
		{
			name: "invalid-time-expected",
			mutate: func(cfg *Config) {
				rule := cfg.PluginRules["sqli_order_by"]
				for index := range rule.Payloads {
					if rule.Payloads[index].Kind == "time_delay" {
						rule.Payloads[index].Expected = "slow"
						break
					}
				}
				cfg.PluginRules["sqli_order_by"] = rule
			},
			match: "expected",
		},
		{
			name: "invalid-kind",
			mutate: func(cfg *Config) {
				rule := cfg.PluginRules["sqli"]
				rule.Payloads[0].Kind = "sql_magic"
				cfg.PluginRules["sqli"] = rule
			},
			match: "kind",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := Default()
			testCase.mutate(&cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), testCase.match) {
				t.Fatalf("expected SQL lint error containing %q, got %v", testCase.match, err)
			}
		})
	}
}

func TestV24SQLRuleLintAllowsBalancedSameGroupVariants(t *testing.T) {
	cfg := Default()
	rule := cfg.PluginRules["sqli_limit"]
	rule.Payloads = append(rule.Payloads,
		PayloadRule{Name: "同组第二破坏", Kind: "error_break", Group: "mysql-limit-comment", Payload: "({{value}}')"},
		PayloadRule{Name: "同组第二恢复", Kind: "error_repair", Group: "mysql-limit-comment", Payload: "({{value}})"},
	)
	cfg.PluginRules["sqli_limit"] = rule
	if err := cfg.Validate(); err != nil {
		t.Fatalf("balanced same-group SQL variants should be paired by order: %v", err)
	}
}

func TestConfigRejectsInvalidPluginRule(t *testing.T) {
	cfg := Default()
	rule := cfg.PluginRules["sensitive_data"]
	rule.Patterns = append(rule.Patterns, DetectionRule{Name: "坏规则", Pattern: "["})
	cfg.PluginRules["sensitive_data"] = rule
	if cfg.Validate() == nil {
		t.Fatal("expected invalid plugin regex error")
	}
}

func TestV13ServiceAndDynamicRuleValidation(t *testing.T) {
	cfg := Default()
	cfg.SharedServiceMode = true
	if cfg.Validate() == nil {
		t.Fatal("shared service mode must require an explicit target allowlist")
	}
	cfg.AllowedHosts = []string{"test.example.local"}
	cfg.ConfigWriteAllowedCIDRs = []string{"10.0.0.0/8"}
	cfg.RequestTransforms = []RequestTransform{{Name: "签名", Algorithm: "hmac-sha256", Source: "body", Destination: "header:X-Sign", Secret: "secret"}}
	cfg.ResponseExtractors = []ResponseExtractor{{Name: "刷新 Token", Source: "body", Pattern: `"token":"([^"]+)"`, Destination: "header:X-Token"}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid V1.3 service configuration was rejected: %v", err)
	}
	cfg.ConfigWriteAllowedCIDRs = []string{"invalid"}
	if cfg.Validate() == nil {
		t.Fatal("invalid management CIDR must be rejected")
	}
}

func TestSessionKeyListAcceptsLegacyObjectsAndSavesSimpleArray(t *testing.T) {
	var keys SessionKeyList
	legacy := []byte(`[{"location":"cookie","name":"JSESSIONID"},{"location":"header","name":"Authorization"},{"location":"json","name":"token"},{"location":"query","name":"TOKEN"}]`)
	if err := json.Unmarshal(legacy, &keys); err != nil {
		t.Fatal(err)
	}
	if len(keys) != 3 || keys[0] != "JSESSIONID" || keys[1] != "Authorization" || keys[2] != "token" {
		t.Fatalf("legacy session identifiers were not normalized: %#v", keys)
	}
	encoded, err := json.Marshal(keys)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `["JSESSIONID","Authorization","token"]` {
		t.Fatalf("session keys should save as a simple string array: %s", encoded)
	}
}

func TestDynamicDestinationValidation(t *testing.T) {
	cfg := Default()
	cfg.ResponseExtractors = []ResponseExtractor{{Name: "会话", Source: "header:Set-Cookie", Pattern: `SESSION=([^;]+)`, Destination: "cookie:SESSION"}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("supported cookie destination was rejected: %v", err)
	}
	cfg.ResponseExtractors[0].Destination = "unknown:SESSION"
	if err := cfg.Validate(); err == nil {
		t.Fatal("unsupported dynamic destination was accepted")
	}
}
