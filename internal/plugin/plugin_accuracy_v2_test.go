package plugin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

func TestShiroActiveProbeWithoutVisibleRememberMe(t *testing.T) {
	ctx := testContext(t, "GET / HTTP/1.1\r\nHost: bank.test\r\n\r\n", model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte("ok")})
	ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
		if strings.Contains(request.Header("Cookie"), "jhs-invalid-rememberme") {
			return model.Response{StatusCode: 200, Headers: map[string]string{"set-cookie": "rememberMe=deleteMe"}, Body: []byte("ok")}, nil
		}
		return ctx.Baseline, nil
	}
	findings, err := (Shiro{}).Scan(ctx)
	assertFinding(t, findings, err, "shiro")
}

func TestJavaDeserializationUsesConfiguredParameterAndDowngradesEntry(t *testing.T) {
	ctx := testContext(t, "POST /decode HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/json\r\n\r\n{\"ctpBlob\":\"normal\"}", model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte("ok")})
	ctx.Config.PluginRules["java_deserialization"] = config.PluginRuleConfig{
		ParameterNames: []string{"ctpBlob"},
		Payloads:       []config.PayloadRule{{Name: "stream", Kind: "error_probe", Payload: "rO0ABXNyAANqaHM="}},
		Patterns:       []config.DetectionRule{{Name: "stream error", Pattern: "StreamCorruptedException"}},
	}
	ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
		if strings.Contains(string(request.Body), "rO0AB") {
			return model.Response{StatusCode: 500, Headers: jsonHeader(), Body: []byte("StreamCorruptedException")}, nil
		}
		return ctx.Baseline, nil
	}
	findings, err := (JavaDeserialization{}).Scan(ctx)
	assertFinding(t, findings, err, "java_deserialization")
	if findings[0].Severity != model.SeverityInfo || findings[0].Confidence != model.ConfidenceFirm {
		t.Fatalf("entry signal must be informational, got %+v", findings[0])
	}
}

func TestJSONPolymorphicScansNestedObjects(t *testing.T) {
	ctx := testContext(t, "POST /bind HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/json\r\n\r\n{\"wrapper\":{\"name\":\"alice\"}}", model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte("ok")})
	ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
		body := string(request.Body)
		if strings.Contains(body, `"wrapper":{"@type":"jungle.happy.scan.SafeModeProbe731"`) {
			return model.Response{StatusCode: 500, Headers: jsonHeader(), Body: []byte("com.alibaba.fastjson.JSONException ClassNotFoundException jungle.happy.scan.SafeModeProbe731")}, nil
		}
		return ctx.Baseline, nil
	}
	findings, err := (JSONPolymorphic{}).Scan(ctx)
	assertFinding(t, findings, err, "json_polymorphic")
}

func TestSMSSuccessExplicitFailureWins(t *testing.T) {
	if smsStructuredSuccess([]byte(`{"code":200,"success":false,"msg":"发送失败，请稍后重试"}`)) {
		t.Fatal("explicit failure must override generic code=200")
	}
	if !smsStructuredSuccess([]byte(`{"msg":"发送成功","code":200}`)) {
		t.Fatal("documented success response should be accepted")
	}
}

func TestJWTCandidatesIncludeSessionCookieAndNestedJSON(t *testing.T) {
	header, _ := json.Marshal(map[string]any{"alg": "HS256"})
	claims, _ := json.Marshal(map[string]any{"sub": "alice"})
	token := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims) + ".signature"
	ctx := testContext(t, "POST /check HTTP/1.1\r\nHost: bank.test\r\nCookie: accessToken="+token+"\r\nContent-Type: application/json\r\n\r\n{\"auth\":{\"token\":\""+token+"\"}}", model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte("ok")})
	candidates := jwtCandidates(ctx.Request, ctx.Points)
	if len(candidates) != 2 {
		t.Fatalf("JWT discovery missed cookie or nested JSON: %+v", candidates)
	}
	for _, candidate := range candidates {
		mutated, err := candidate.mutate(ctx.Request, candidate.prefix+"changed.token.value")
		if err != nil || !strings.Contains(mutated.Raw(false), "changed.token.value") {
			t.Fatalf("JWT candidate cannot be mutated: affected=%s err=%v", candidate.affected, err)
		}
	}
}

func TestNewHighConfidencePlugins(t *testing.T) {
	t.Run("jwt-none", func(t *testing.T) {
		header, _ := json.Marshal(map[string]any{"alg": "HS256", "typ": "JWT"})
		claims, _ := json.Marshal(map[string]any{"sub": "alice"})
		token := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims) + ".valid"
		baseline := model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"user":"alice"}`)}
		ctx := testContext(t, "GET /me HTTP/1.1\r\nHost: bank.test\r\nAuthorization: Bearer "+token+"\r\n\r\n", baseline)
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			value := request.Header("Authorization")
			if strings.Contains(value, "jhs_invalid_signature") {
				return model.Response{StatusCode: 401, Headers: jsonHeader(), Body: []byte("unauthorized")}, nil
			}
			return baseline, nil
		}
		findings, err := (JWTActive{}).Scan(ctx)
		assertFinding(t, findings, err, "jwt_active")
	})

	t.Run("proxy-trust", func(t *testing.T) {
		baseline := model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"balance":731}`)}
		ctx := testContext(t, "GET /private HTTP/1.1\r\nHost: bank.test\r\nCookie: JSESSIONID=valid\r\n\r\n", baseline)
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			if request.Header("Cookie") == "" && request.Header("X-Forwarded-For") == "" {
				return model.Response{StatusCode: 401, Headers: jsonHeader(), Body: []byte("unauthorized")}, nil
			}
			return baseline, nil
		}
		findings, err := (ProxyTrustBypass{}).Scan(ctx)
		assertFinding(t, findings, err, "proxy_trust_bypass")
	})

	t.Run("trace", func(t *testing.T) {
		ctx := testContext(t, "GET / HTTP/1.1\r\nHost: bank.test\r\n\r\n", model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte("ok")})
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			return model.Response{StatusCode: 200, Headers: map[string]string{"content-type": "message/http"}, Body: []byte("TRACE / HTTP/1.1\r\nX-Jungle-Trace: " + request.Header("X-Jungle-Trace"))}, nil
		}
		findings, err := (HTTPTrace{}).Scan(ctx)
		assertFinding(t, findings, err, "http_trace")
	})
}
