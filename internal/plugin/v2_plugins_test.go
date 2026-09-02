package plugin

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"jungle_happy_Scan/internal/callback"
	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

func v2Context(t *testing.T, raw string) *Context {
	t.Helper()
	cfg := config.Default()
	request, err := httpraw.Parse(raw, "http")
	if err != nil {
		t.Fatal(err)
	}
	return &Context{
		Context: context.Background(), Request: request, Baseline: model.Response{StatusCode: 200, Headers: map[string]string{}, Body: []byte(`{"ok":true}`)},
		Baselines: []model.Response{{StatusCode: 200, Headers: map[string]string{}, Body: []byte(`{"ok":true}`)}},
		Points:    httpraw.DiscoverAdvanced(request, cfg), Mode: "deep", Config: cfg, Callbacks: callback.New(), Progress: func(string, int, int) {},
	}
}

func TestCallbackWaitBatchUsesOneTimeoutWindow(t *testing.T) {
	registry := callback.New()
	var tokens []string
	for range 5 {
		token, _ := registry.Register("http://127.0.0.1:61166", "ssrf")
		tokens = append(tokens, token)
	}
	started := time.Now()
	hits := waitCallbackBatch(context.Background(), registry, tokens, 25*time.Millisecond)
	if elapsed := time.Since(started); elapsed >= 80*time.Millisecond {
		t.Fatalf("callback waits were serialized: %s", elapsed)
	}
	for _, token := range tokens {
		if hits[token] {
			t.Fatalf("unexpected callback hit for %s", token)
		}
	}
}

func TestShiroDefaultKeyUsesSafeNullStream(t *testing.T) {
	ctx := v2Context(t, "GET / HTTP/1.1\r\nHost: example.test\r\nCookie: rememberMe=old\r\n\r\n")
	ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
		response := model.Response{StatusCode: 200, Headers: map[string]string{}, Body: []byte("ok")}
		if strings.Contains(request.Header("Cookie"), "jhs-invalid-rememberme") {
			response.Headers["set-cookie"] = "rememberMe=deleteMe; Path=/"
		}
		return response, nil
	}
	findings, err := (Shiro{}).Scan(ctx)
	if err != nil || len(findings) != 2 || findings[1].Severity != model.SeverityCritical {
		t.Fatalf("err=%v findings=%+v", err, findings)
	}
}

func TestJavaExpressionRequiresTwoEvaluatedResults(t *testing.T) {
	ctx := v2Context(t, "GET /search?q=test HTTP/1.1\r\nHost: example.test\r\n\r\n")
	ctx.Config.PluginRules["java_expression"] = config.PluginRuleConfig{Payloads: []config.PayloadRule{{Name: "SpEL", Payload: "${{{left}}*{{right}}}"}}}
	expression := regexp.MustCompile(`\$\{(\d+)\*(\d+)\}`)
	ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
		parsed, _ := url.Parse(request.Target)
		match := expression.FindStringSubmatch(parsed.Query().Get("q"))
		body := "not evaluated"
		if len(match) == 3 {
			left, _ := strconv.Atoi(match[1])
			right, _ := strconv.Atoi(match[2])
			body = fmt.Sprint(left * right)
		}
		return model.Response{StatusCode: 200, Headers: map[string]string{}, Body: []byte(body)}, nil
	}
	findings, err := (JavaExpression{}).Scan(ctx)
	if err != nil || len(findings) != 1 || len(findings[0].Evidence) != 2 {
		t.Fatalf("err=%v findings=%+v", err, findings)
	}
}

func TestJNDICallbackIsConfirmedWithoutServingObject(t *testing.T) {
	ctx := v2Context(t, "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
	ctx.Config.CallbackLDAPBaseURL = "ldap://127.0.0.1:61167"
	ctx.Config.PluginRules["jndi_injection"] = config.PluginRuleConfig{Payloads: []config.PayloadRule{{Name: "header", Header: "User-Agent", Payload: "${jndi:{{callback}}}"}}}
	ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
		ctx.Callbacks.HitFromBytes([]byte(request.Header("User-Agent")))
		return model.Response{StatusCode: 200, Headers: map[string]string{}, Body: []byte("ok")}, nil
	}
	findings, err := (JNDIInjection{}).Scan(ctx)
	if err != nil || len(findings) != 1 || findings[0].Evidence[0].Strength != "L5" {
		t.Fatalf("err=%v findings=%+v", err, findings)
	}
}

func TestJNDIHeaderlessRuleCoversEveryInsertionPoint(t *testing.T) {
	ctx := v2Context(t, "GET /search?a=one&b=two HTTP/1.1\r\nHost: example.test\r\n\r\n")
	ctx.Config.CallbackLDAPBaseURL = "ldap://127.0.0.1:61167"
	ctx.Config.PluginRules["jndi_injection"] = config.PluginRuleConfig{Payloads: []config.PayloadRule{{Name: "parameter", Payload: "${jndi:{{callback}}}"}}}
	sends := 0
	ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
		sends++
		ctx.Callbacks.HitFromBytes([]byte(request.Target))
		return model.Response{StatusCode: 200, Headers: map[string]string{}, Body: []byte("ok")}, nil
	}
	findings, err := (JNDIInjection{}).Scan(ctx)
	if err != nil || sends != len(ctx.Points) || len(findings) != len(ctx.Points) {
		t.Fatalf("headerless JNDI rule did not cover all points: sends=%d points=%d err=%v findings=%+v", sends, len(ctx.Points), err, findings)
	}
}

func TestHostHeaderInjectionRequiresRepeatedAbsoluteURL(t *testing.T) {
	ctx := v2Context(t, "GET /reset HTTP/1.1\r\nHost: example.test\r\n\r\n")
	ctx.Config.PluginRules["host_header_injection"] = config.PluginRuleConfig{Payloads: []config.PayloadRule{{Name: "forwarded", Header: "X-Forwarded-Host", Payload: "{{host}}"}}}
	ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
		host := request.Header("X-Forwarded-Host")
		return model.Response{StatusCode: 302, Headers: map[string]string{"location": "https://" + host + "/login"}}, nil
	}
	findings, err := (HostHeaderInjection{}).Scan(ctx)
	if err != nil || len(findings) != 1 {
		t.Fatalf("err=%v findings=%+v", err, findings)
	}
}

func TestSSRFReflectedCallbackURLIsNotAFinding(t *testing.T) {
	ctx := v2Context(t, "GET /fetch?url=old HTTP/1.1\r\nHost: example.test\r\n\r\n")
	ctx.Config.CallbackBaseURL = "http://127.0.0.1:61166"
	ctx.Config.PluginRules["ssrf"] = config.PluginRuleConfig{
		ParameterNames: []string{"url"},
		Payloads:       []config.PayloadRule{{Name: "callback", Payload: "{{callback}}"}},
	}
	ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
		parsed, _ := url.Parse(request.Target)
		return model.Response{StatusCode: 200, Headers: map[string]string{}, Body: []byte(`{"url":"` + parsed.Query().Get("url") + `"}`)}, nil
	}
	findings, err := (SSRF{}).Scan(ctx)
	if err != nil || len(findings) != 0 {
		t.Fatalf("reflected callback URL must not confirm SSRF: err=%v findings=%+v", err, findings)
	}
}

func TestSSRFCallbackResponseMarkerConfirmsInBandFetch(t *testing.T) {
	ctx := v2Context(t, "POST /fetch HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n\r\n{\"cmcDomain\":\"123\"}")
	ctx.Config.CallbackBaseURL = "http://127.0.0.1:61166"
	ctx.Config.PluginRules["ssrf"] = config.PluginRuleConfig{
		ParameterNames: []string{"domain"},
		Payloads:       []config.PayloadRule{{Name: "callback", Payload: "{{callback}}"}},
	}
	ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
		tokens := callback.TokensFromText(string(request.Body))
		if len(tokens) != 1 {
			t.Fatalf("mutated JSON did not contain one callback token: %s", request.Body)
		}
		body := `{"upstream":"` + callback.ResponseMarker(tokens[0]) + `"}`
		return model.Response{StatusCode: 200, Headers: map[string]string{}, Body: []byte(body)}, nil
	}
	findings, err := (SSRF{}).Scan(ctx)
	if err != nil || len(findings) != 1 {
		t.Fatalf("in-band callback response was not confirmed: err=%v findings=%+v", err, findings)
	}
	if findings[0].Title != "服务端读取并回显 SSRF 回连内容" {
		t.Fatalf("unexpected in-band SSRF title: %#v", findings[0])
	}
}
