package plugin

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

func TestV131SpringAndMyBatisPlugins(t *testing.T) {
	t.Run("method-override-does-not-report-ignored-header", func(t *testing.T) {
		baseline := model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"ok":true}`)}
		ctx := testContext(t, "POST /account HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/json\r\n\r\n{}", baseline)
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			if request.Method == "DELETE" {
				return model.Response{StatusCode: 405, Headers: jsonHeader(), Body: []byte(`{"error":"denied"}`)}, nil
			}
			return baseline, nil
		}
		findings, err := (MethodOverride{}).Scan(ctx)
		if err != nil || len(findings) != 0 {
			t.Fatalf("ignored override header must not alert: findings=%d err=%v", len(findings), err)
		}
	})

	t.Run("spring-form-method-override", func(t *testing.T) {
		baseline := model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"editing":true}`)}
		ctx := testContext(t, "POST /account HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nname=alice", baseline)
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			if request.Method == "DELETE" {
				return model.Response{StatusCode: 405, Headers: jsonHeader(), Body: []byte(`{"error":"denied"}`)}, nil
			}
			values, _ := url.ParseQuery(string(request.Body))
			if values.Get("_method") == "DELETE" {
				return model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"deleted":true}`)}, nil
			}
			return baseline, nil
		}
		findings, err := (MethodOverride{}).Scan(ctx)
		assertFinding(t, findings, err, "method_override")
	})

	t.Run("mass-assignment-root-json-array", func(t *testing.T) {
		baseline := model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`[{"name":"alice"}]`)}
		ctx := testContext(t, "PATCH /users HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/json\r\n\r\n[{\"name\":\"alice\"}]", baseline)
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			if strings.Contains(string(request.Body), `"isAdmin":true`) {
				return model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`[{"name":"alice","isAdmin":true}]`)}, nil
			}
			return baseline, nil
		}
		findings, err := (MassAssignment{}).Scan(ctx)
		assertFinding(t, findings, err, "mass_assignment")
		if !strings.HasPrefix(findings[0].Affected, "json:[0]") {
			t.Fatalf("expected JSON array location, got %q", findings[0].Affected)
		}
	})

	t.Run("mybatis-dynamic-fragment", func(t *testing.T) {
		baseline := model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"rows":[1,2]}`)}
		ctx := testContext(t, "GET /users?orderBy=name HTTP/1.1\r\nHost: bank.test\r\n\r\n", baseline)
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			if strings.Contains(request.Target, "jhs_invalid_column_731") {
				return model.Response{StatusCode: 500, Headers: jsonHeader(), Body: []byte("org.springframework.jdbc.BadSqlGrammarException: Unknown column 'jhs_invalid_column_731' in 'order clause'")}, nil
			}
			return baseline, nil
		}
		findings, err := (MyBatisDynamicSQL{}).Scan(ctx)
		assertFinding(t, findings, err, "mybatis_dynamic_sql")
	})

	t.Run("mybatis-reuses-baselines-and-sends-only-canaries", func(t *testing.T) {
		baseline := model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"debug":"BadSqlGrammarException","rows":[1,2]}`)}
		ctx := testContext(t, "POST /users HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/json\r\n\r\n{\"page\":{\"sort_field\":\"name\"}}", baseline)
		ctx.Baselines = []model.Response{baseline, baseline}
		rule := ctx.Config.PluginRules["mybatis_dynamic_sql"]
		rule.Patterns = append([]config.DetectionRule{{
			Name: "基线已有泛化框架文本", Pattern: `BadSqlGrammarException`,
			Severity: "high", Confidence: "firm",
		}}, rule.Patterns...)
		rule.Payloads = append(rule.Payloads, config.PayloadRule{
			Name: "遗留深度变体", Kind: "fragment_break", Payload: "{{value}} DESC,jhs_deep_should_not_run",
			Expected: "jhs_deep_should_not_run", Mode: "deep",
		})
		ctx.Config.PluginRules["mybatis_dynamic_sql"] = rule
		sends := 0
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			sends++
			body := string(request.Body)
			if strings.Contains(body, "jhs_deep_should_not_run") {
				t.Fatal("legacy mode=deep MyBatis payload ran implicitly")
			}
			if strings.Contains(body, "jhs_invalid_column_731") {
				return model.Response{StatusCode: 500, Headers: jsonHeader(), Body: []byte(`BadSqlGrammarException: column "jhs_invalid_column_731" does not exist`)}, nil
			}
			t.Fatalf("MyBatis scanner resent the original POST body: %s", body)
			return baseline, nil
		}
		findings, err := (MyBatisDynamicSQL{}).Scan(ctx)
		assertFinding(t, findings, err, "mybatis_dynamic_sql")
		if sends != 2 {
			t.Fatalf("MyBatis ABBA must reuse two baseline responses and send only two canaries, sends=%d", sends)
		}
	})
}

func TestV131AuthorizationAndDeserializerPlugins(t *testing.T) {
	t.Run("path-normalization-bypass", func(t *testing.T) {
		baseline := model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"account":"alice","balance":731}`)}
		ctx := testContext(t, "GET /secure/account HTTP/1.1\r\nHost: bank.test\r\nCookie: JSESSIONID=valid\r\n\r\n", baseline)
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			if request.Header("Cookie") == "" {
				if strings.Contains(request.Target, ";jhs=1") {
					return baseline, nil
				}
				return model.Response{StatusCode: 401, Headers: jsonHeader(), Body: []byte(`{"error":"unauthorized"}`)}, nil
			}
			return baseline, nil
		}
		findings, err := (PathNormalization{}).Scan(ctx)
		assertFinding(t, findings, err, "path_normalization")
	})

	t.Run("session-precedence-confusion", func(t *testing.T) {
		baseline := model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"account":"alice","authenticated":true}`)}
		ctx := testContext(t, "GET /secure?sessionId=valid HTTP/1.1\r\nHost: bank.test\r\n\r\n", baseline)
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			parsed, _ := url.Parse(request.Target)
			values := parsed.Query()["sessionId"]
			if len(values) > 0 && values[len(values)-1] == "valid" {
				return baseline, nil
			}
			return model.Response{StatusCode: 401, Headers: jsonHeader(), Body: []byte(`{"error":"unauthorized"}`)}, nil
		}
		findings, err := (ParameterConfusion{}).Scan(ctx)
		assertFinding(t, findings, err, "parameter_confusion")
		if findings[0].Confidence != model.ConfidenceCertain {
			t.Fatalf("session precedence should be certain: %#v", findings[0])
		}
	})

	t.Run("jackson-polymorphic-entry", func(t *testing.T) {
		baseline := model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"ok":true}`)}
		ctx := testContext(t, "POST /convert HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/json\r\n\r\n{\"name\":\"alice\"}", baseline)
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			if strings.Contains(string(request.Body), `"@class"`) || strings.Contains(string(request.Body), `"@type"`) {
				return model.Response{StatusCode: 400, Headers: jsonHeader(), Body: []byte("com.fasterxml.jackson.databind.exc.InvalidTypeIdException: Could not resolve type id 'jungle.happy.scan.DoesNotExist731' as a subtype")}, nil
			}
			return baseline, nil
		}
		findings, err := (JSONPolymorphic{}).Scan(ctx)
		if err != nil || len(findings) != 0 {
			t.Fatalf("V2.3 Fastjson-only SafeMode plugin must ignore Jackson: findings=%#v err=%v", findings, err)
		}
	})

	t.Run("fastjson-safemode-blocked", func(t *testing.T) {
		baseline := model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"ok":true}`)}
		ctx := testContext(t, "POST /convert HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/json\r\n\r\n{\"name\":\"alice\"}", baseline)
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			if strings.Contains(string(request.Body), `"@type"`) {
				return model.Response{StatusCode: 500, Headers: jsonHeader(), Body: []byte(`{"error":"JSONException","message":"safeMode not support autotype: jungle.happy.scan.SafeModeProbe731"}`)}, nil
			}
			return baseline, nil
		}
		findings, err := (JSONPolymorphic{}).Scan(ctx)
		if err != nil || len(findings) != 0 {
			t.Fatalf("enabled Fastjson SafeMode must be a secure no-finding result: findings=%#v err=%v", findings, err)
		}
	})

	t.Run("fastjson-class-load-attempt", func(t *testing.T) {
		baseline := model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"ok":true}`)}
		ctx := testContext(t, "POST /convert HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/json\r\n\r\n{\"name\":\"alice\"}", baseline)
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			if strings.Contains(string(request.Body), `"@type"`) {
				return model.Response{StatusCode: 500, Headers: jsonHeader(), Body: []byte(`com.alibaba.fastjson.JSONException: java.lang.ClassNotFoundException: jungle.happy.scan.SafeModeProbe731`)}, nil
			}
			return baseline, nil
		}
		findings, err := (JSONPolymorphic{}).Scan(ctx)
		assertFinding(t, findings, err, "json_polymorphic")
		if findings[0].Severity != model.SeverityHigh || findings[0].Confidence != model.ConfidenceCertain ||
			!strings.Contains(findings[0].Title, "未开启 SafeMode") {
			t.Fatalf("Fastjson SafeMode absence was misclassified: %#v", findings[0])
		}
	})
}
