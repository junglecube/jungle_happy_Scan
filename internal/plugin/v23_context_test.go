package plugin

import (
	"context"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

func TestCommandInjectionBackuppathBacktickCallback(t *testing.T) {
	ctx := testContext(t,
		"POST /backup HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/json\r\n\r\n{\"backuppath\":\"/safe/backup\"}",
		model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"code":0}`)})
	ctx.Config.CallbackBaseURL = "http://scanner.test:61166"
	ctx.Config.CommandParameterNames = []string{"backuppath"}
	ctx.Config.PluginRules["command_injection_oast"] = config.PluginRuleConfig{
		Payloads: []config.PayloadRule{{
			Name: "反引号 curl 离线回连", Kind: "callback",
			Payload: "`curl -fsS --max-time 3 '{{callback}}' >/dev/null`",
		}},
	}
	tokenPattern := regexp.MustCompile(`jhs-command-[0-9a-f]{24}`)
	ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
		var body map[string]string
		if err := json.Unmarshal(request.Body, &body); err != nil {
			t.Fatalf("mutated JSON is invalid: %v body=%q", err, request.Body)
		}
		value := body["backuppath"]
		if strings.HasPrefix(value, "`curl ") && strings.HasSuffix(value, "`") {
			if token := tokenPattern.FindString(value); token != "" {
				ctx.Callbacks.Hit(token)
			}
		}
		return ctx.Baseline, nil
	}
	findings, err := (CommandInjectionOAST{}).Scan(ctx)
	assertFinding(t, findings, err, "command_injection_oast")
	if !strings.Contains(strings.ToLower(findings[0].Affected), "backuppath") {
		t.Fatalf("backuppath callback finding has wrong affected point: %#v", findings[0])
	}
}

func TestCommandInjectionDefaultShellContexts(t *testing.T) {
	cfg := config.Default()
	for _, pluginID := range []string{"command_injection", "command_injection_oast", "command_injection_timing"} {
		if !semanticName("backuppath", cfg.PluginRules[pluginID].ParameterNames) {
			t.Fatalf("%s does not select backuppath", pluginID)
		}
	}
	required := map[string]bool{
		"反引号 curl 离线回连": false, "美元括号 curl 离线回连": false,
		"管道 curl 离线回连": false, "逻辑或 curl 离线回连": false,
		"逻辑与 curl 离线回连": false, "换行 curl 离线回连": false,
	}
	for _, payload := range cfg.PluginRules["command_injection_oast"].Payloads {
		if _, ok := required[payload.Name]; ok {
			required[payload.Name] = true
		}
	}
	for name, found := range required {
		if !found {
			t.Fatalf("default command callback context %q is missing", name)
		}
	}
	if pairs := pairPayloads(cfg.PluginRules["command_injection_timing"].Payloads, "delay", "control"); len(pairs) < 8 {
		t.Fatalf("command timing contexts are incomplete: %d pairs", len(pairs))
	}
}

func TestV23DirectRuntimeExecContext(t *testing.T) {
	ctx := testContext(t, "POST /run HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/json\r\n\r\n{\"command\":\"status\"}",
		model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte("idle")})
	expr := regexp.MustCompile(`expr\s+([0-9]+)\s+\+\s+([0-9]+)`)
	ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
		match := expr.FindStringSubmatch(string(request.Body))
		if len(match) == 3 {
			left, _ := strconv.Atoi(match[1])
			right, _ := strconv.Atoi(match[2])
			return model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(strconv.Itoa(left + right))}, nil
		}
		return ctx.Baseline, nil
	}
	findings, err := (CommandInjection{}).Scan(ctx)
	assertFinding(t, findings, err, "command_injection")
}

func TestV23RawJavaExpressionContext(t *testing.T) {
	ctx := testContext(t, "POST /eval HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/json\r\n\r\n{\"expression\":\"name\"}",
		model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte("idle")})
	ctx.Config.PluginRules["java_expression"] = config.PluginRuleConfig{Payloads: []config.PayloadRule{
		{Name: "Groovy/ScriptEngine", Kind: "raw_expression", Payload: "{{left}}*{{right}}"},
	}}
	product := regexp.MustCompile(`"expression":"([0-9]+)\*([0-9]+)"`)
	ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
		match := product.FindStringSubmatch(string(request.Body))
		if len(match) == 3 {
			left, _ := strconv.Atoi(match[1])
			right, _ := strconv.Atoi(match[2])
			return model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(strconv.Itoa(left * right))}, nil
		}
		return ctx.Baseline, nil
	}
	findings, err := (JavaExpression{}).Scan(ctx)
	assertFinding(t, findings, err, "java_expression")
}

func TestV23SQLContextSelection(t *testing.T) {
	if got := classifySQLContext(httpraw.InsertionPoint{Location: "json", Name: "searchKeyword", Value: "alice", ValueType: "string"}); got != "like-string" {
		t.Fatalf("MyBatis LIKE-style parameter classified as %q", got)
	}
	pairs := []payloadPair{
		{group: "mysql-order-field-exp"},
		{group: "mysql-order-direction-exp"},
	}
	field := orderByPairsForPoint(pairs, httpraw.InsertionPoint{Name: "sortField", Value: "createdAt"})
	direction := orderByPairsForPoint(pairs, httpraw.InsertionPoint{Name: "sortOrder", Value: "DESC"})
	if len(field) != 1 || field[0].group != "mysql-order-field-exp" ||
		len(direction) != 1 || direction[0].group != "mysql-order-direction-exp" {
		t.Fatalf("ORDER BY context split failed: field=%#v direction=%#v", field, direction)
	}
}

func TestV23MIMESniffingDoesNotPromoteTextPlainToXSS(t *testing.T) {
	if xssHTMLResponse("text/plain; charset=utf-8", "<html><body>text</body></html>") {
		t.Fatal("explicit text/plain must not be classified as executable HTML")
	}
	ctx := testContext(t, "GET /legacy.jsp HTTP/1.1\r\nHost: bank.test\r\n\r\n",
		model.Response{StatusCode: 200, Headers: map[string]string{}, Body: []byte("<html><body>legacy</body></html>")})
	findings, err := (SecurityHeaders{}).Scan(ctx)
	assertFinding(t, findings, err, "security_headers")
	if !strings.Contains(findings[0].Description, "Content-Type") {
		t.Fatalf("missing Content-Type MIME risk not included: %#v", findings[0])
	}
}
