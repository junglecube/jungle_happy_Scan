package plugin

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"jungle_happy_Scan/internal/callback"
	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

func TestRequestedPluginDetections(t *testing.T) {
	t.Run("unauthorized", func(t *testing.T) {
		ctx := testContext(t, "GET /private HTTP/1.1\r\nHost: bank.test\r\nCookie: JSESSIONID=secret\r\n\r\n", model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"code":"000000","data":{"balance":100}}`)})
		ctx.SendFunc = func(context.Context, *httpraw.Request) (model.Response, error) { return ctx.Baseline, nil }
		findings, err := (Unauthorized{}).Scan(ctx)
		assertFinding(t, findings, err, "unauthorized")
	})

	t.Run("unauthorized-removes-custom-session-before-cookie-conclusion", func(t *testing.T) {
		ctx := testContext(t, "GET /private HTTP/1.1\r\nHost: bank.test\r\nCookie: theme=dark\r\ndesSessionId: real-session\r\n\r\n", model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"code":"000000","data":{"balance":100}}`)})
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			if request.Header("desSessionId") == "real-session" {
				return ctx.Baseline, nil
			}
			return model.Response{StatusCode: 401, Headers: jsonHeader(), Body: []byte(`{"code":"401","message":"未登录"}`)}, nil
		}
		findings, err := (Unauthorized{}).Scan(ctx)
		if err != nil || len(findings) != 0 {
			t.Fatalf("custom authentication header was left valid and caused a false finding: findings=%#v err=%v", findings, err)
		}
	})

	t.Run("unauthorized-without-any-credential", func(t *testing.T) {
		ctx := testContext(t, "GET /private HTTP/1.1\r\nHost: bank.test\r\n\r\n", model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"code":"000000","data":{"balance":100}}`)})
		findings, err := (Unauthorized{}).Scan(ctx)
		assertFinding(t, findings, err, "unauthorized")
		if findings[0].Affected != "request" {
			t.Fatalf("credential-free unauthorized finding has wrong affected location: %#v", findings[0])
		}
	})

	t.Run("xxe-file-read", func(t *testing.T) {
		raw := "POST /xml HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/xml\r\n\r\n<root><name>alice</name></root>"
		ctx := testContext(t, raw, model.Response{StatusCode: 200, Headers: map[string]string{"content-type": "application/xml"}, Body: []byte("<ok/>")})
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			if strings.Contains(string(request.Body), "file:///etc/passwd") {
				return model.Response{StatusCode: 200, Headers: map[string]string{}, Body: []byte("root:x:0:0:root:/root:/bin/bash\n")}, nil
			}
			return model.Response{StatusCode: 200, Headers: map[string]string{}, Body: []byte("ok")}, nil
		}
		findings, err := (XXE{}).Scan(ctx)
		assertFinding(t, findings, err, "xxe")
	})

	t.Run("path-traversal", func(t *testing.T) {
		ctx := testContext(t, "GET /download?filepath=report.pdf HTTP/1.1\r\nHost: bank.test\r\n\r\n", model.Response{StatusCode: 200, Headers: map[string]string{}, Body: []byte("report")})
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			u, _ := url.Parse(request.Target)
			if strings.Contains(u.Query().Get("filepath"), "etc/passwd") {
				return model.Response{StatusCode: 200, Headers: map[string]string{}, Body: []byte("root:x:0:0:root:/root:/bin/bash\n")}, nil
			}
			return ctx.Baseline, nil
		}
		findings, err := (FileRead{}).Scan(ctx)
		assertFinding(t, findings, err, "file_read")
	})

	t.Run("hosts-readable-when-passwd-is-blocked", func(t *testing.T) {
		ctx := testContext(t, "GET /download?filepath=report.pdf HTTP/1.1\r\nHost: bank.test\r\n\r\n", model.Response{StatusCode: 200, Headers: map[string]string{}, Body: []byte("report")})
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			u, _ := url.Parse(request.Target)
			switch {
			case strings.Contains(u.Query().Get("filepath"), "etc/passwd"):
				return model.Response{StatusCode: 403, Headers: map[string]string{}, Body: []byte("blocked")}, nil
			case strings.Contains(u.Query().Get("filepath"), "etc/hosts"):
				return model.Response{StatusCode: 200, Headers: map[string]string{}, Body: []byte("127.0.0.1 localhost\n::1 localhost ip6-localhost\n")}, nil
			default:
				return ctx.Baseline, nil
			}
		}
		findings, err := (FileRead{}).Scan(ctx)
		assertFinding(t, findings, err, "file_read")
		if len(findings[0].Evidence) != 2 || !strings.Contains(findings[0].Evidence[0].Summary, "hosts") {
			t.Fatalf("hosts read was not independently repeated: %#v", findings[0])
		}
	})

	t.Run("dangerous-upload", func(t *testing.T) {
		body := "--abc\r\nContent-Disposition: form-data; name=\"file\"; filename=\"safe.txt\"\r\nContent-Type: text/plain\r\n\r\nsafe\r\n--abc--\r\n"
		raw := "POST /upload HTTP/1.1\r\nHost: bank.test\r\nContent-Type: multipart/form-data; boundary=abc\r\n\r\n" + body
		ctx := testContext(t, raw, model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"code":"400","message":"bad type"}`)})
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			if strings.Contains(string(request.Body), ".jsp") || strings.Contains(string(request.Body), ".exe") {
				return model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"code":"000000","message":"上传成功"}`)}, nil
			}
			return ctx.Baseline, nil
		}
		findings, err := (FileUpload{}).Scan(ctx)
		assertFinding(t, findings, err, "file_upload")
	})

	t.Run("sensitive-data", func(t *testing.T) {
		body := `{"phone":"13800138000","id":"11010519491231002X","card":"4111111111111111","email":"ops@example.com","appSecret":"wxSecret_731_abcdefghijkl"}` +
			"\n at com.bank.UserService.query(UserService.java:81)" +
			"\n/var/run/secrets/kubernetes.io/serviceaccount/token" +
			"\n{\"auths\":{\"registry.internal\":{\"auth\":\"dXNlcjpwYXNzd29yZA==\"}}}"
		ctx := testContext(t, "GET /data HTTP/1.1\r\nHost: bank.test\r\n\r\n", model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(body)})
		findings, err := (SensitiveData{}).Scan(ctx)
		if err != nil || len(findings) < 7 {
			t.Fatalf("expected multiple validated sensitive findings, got %d, err=%v", len(findings), err)
		}
		for _, expected := range []string{"邮箱地址", "Kubernetes ServiceAccount", "Docker Registry", "微信小程序 AppSecret"} {
			found := false
			for _, finding := range findings {
				found = found || strings.Contains(finding.Title, expected)
			}
			if !found {
				t.Fatalf("missing %s sensitive finding: %#v", expected, findings)
			}
		}
	})

	t.Run("cors", func(t *testing.T) {
		ctx := testContext(t, "GET /private HTTP/1.1\r\nHost: bank.test\r\nCookie: JSESSIONID=x\r\n\r\n", model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"secret":1}`)})
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			return model.Response{StatusCode: 200, Headers: map[string]string{"access-control-allow-origin": request.Header("Origin"), "access-control-allow-credentials": "true"}, Body: []byte(`{"secret":1}`)}, nil
		}
		findings, err := (CORS{}).Scan(ctx)
		assertFinding(t, findings, err, "cors")
	})

	t.Run("reflected-xss", func(t *testing.T) {
		render := func(value string) string {
			lines := make([]string, 100)
			for index := range lines {
				lines[index] = fmt.Sprintf("<!-- layout-%d -->", index)
			}
			lines[0] = "<html>"
			lines[1] = strings.Repeat("outside-window-", 5000)
			lines[50] = "<script>var reflected = '" + value + "';</script>"
			lines[99] = "</html>"
			return strings.Join(lines, "\n")
		}
		ctx := testContext(t, "GET /search?q=hello HTTP/1.1\r\nHost: bank.test\r\n\r\n", model.Response{StatusCode: 200, Headers: htmlHeader(), Body: []byte(render("hello"))})
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			u, _ := url.Parse(request.Target)
			return model.Response{StatusCode: 200, Headers: htmlHeader(), Body: []byte(render(u.Query().Get("q")))}, nil
		}
		findings, err := (ReflectedXSS{}).Scan(ctx)
		assertFinding(t, findings, err, "reflected_xss")
		if len(findings[0].Evidence) != 2 {
			t.Fatalf("reflected XSS evidence count = %d, want 2", len(findings[0].Evidence))
		}
		for index, evidence := range findings[0].Evidence {
			if evidence.ResponseContextStrategy != "marker_lines" || !evidence.ResponseContextClipped || evidence.ResponseContextStartLine != 21 || evidence.ResponseContextEndLine != 81 {
				t.Fatalf("reflected XSS evidence %d is not centered on the marker: %#v", index, evidence)
			}
		}
	})
}

func TestAdditionalHighConfidencePlugins(t *testing.T) {
	t.Run("open-redirect", func(t *testing.T) {
		ctx := testContext(t, "GET /login?redirect=%2Fhome HTTP/1.1\r\nHost: bank.test\r\n\r\n", model.Response{StatusCode: 302, Headers: map[string]string{"location": "/home"}})
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			u, _ := url.Parse(request.Target)
			return model.Response{StatusCode: 302, Headers: map[string]string{"location": u.Query().Get("redirect")}}, nil
		}
		findings, err := (OpenRedirect{}).Scan(ctx)
		assertFinding(t, findings, err, "open_redirect")
	})

	t.Run("ssti", func(t *testing.T) {
		ctx := testContext(t, "GET /hello?name=user HTTP/1.1\r\nHost: bank.test\r\n\r\n", model.Response{StatusCode: 200, Headers: htmlHeader(), Body: []byte("hello user")})
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			u, _ := url.Parse(request.Target)
			body := "hello " + u.Query().Get("name")
			if match := regexp.MustCompile(`\{\{(\d+)\*(\d+)\}\}`).FindStringSubmatch(body); len(match) == 3 {
				left, _ := strconv.Atoi(match[1])
				right, _ := strconv.Atoi(match[2])
				body = fmt.Sprintf("hello %d", left*right)
			}
			return model.Response{StatusCode: 200, Headers: htmlHeader(), Body: []byte(body)}, nil
		}
		findings, err := (SSTI{}).Scan(ctx)
		assertFinding(t, findings, err, "ssti")
	})
}

func TestWebConfiguredRulesAreUsed(t *testing.T) {
	t.Run("custom-file-read-payload", func(t *testing.T) {
		ctx := testContext(t, "GET /download?resourceKey=report HTTP/1.1\r\nHost: bank.test\r\n\r\n", model.Response{StatusCode: 200, Headers: map[string]string{}, Body: []byte("normal")})
		ctx.Config.PluginRules["file_read"] = config.PluginRuleConfig{
			ParameterNames: []string{"resourceKey"},
			Payloads:       []config.PayloadRule{{Name: "管理员新增 payload", Payload: "/opt/app/custom.secret", Expected: "CUSTOM_SECRET_MARKER"}},
		}
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			u, _ := url.Parse(request.Target)
			if u.Query().Get("resourceKey") == "/opt/app/custom.secret" {
				return model.Response{StatusCode: 200, Headers: map[string]string{}, Body: []byte("CUSTOM_SECRET_MARKER")}, nil
			}
			return ctx.Baseline, nil
		}
		findings, err := (FileRead{}).Scan(ctx)
		assertFinding(t, findings, err, "file_read")
		if !strings.HasPrefix(findings[0].Evidence[0].Response, "HTTP/1.1 200 OK\r\n") || !strings.Contains(findings[0].Evidence[0].Response, "\r\n\r\nCUSTOM_SECRET_MARKER") {
			t.Fatalf("response evidence is not status/header/body order: %q", findings[0].Evidence[0].Response)
		}
	})

	t.Run("custom-sensitive-pattern", func(t *testing.T) {
		ctx := testContext(t, "GET /data HTTP/1.1\r\nHost: bank.test\r\n\r\n", model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"customerCode":"CUST-73193"}`)})
		ctx.Config.PluginRules["sensitive_data"] = config.PluginRuleConfig{Patterns: []config.DetectionRule{{Name: "客户编号", Pattern: `CUST-\d{5}`, Severity: "medium", Confidence: "certain"}}}
		findings, err := (SensitiveData{}).Scan(ctx)
		assertFinding(t, findings, err, "sensitive_data")
		if findings[0].Title != "响应泄露客户编号" {
			t.Fatalf("custom sensitive rule was not used: %#v", findings[0])
		}
	})
}

func TestPluginBehaviorDoesNotDependOnMode(t *testing.T) {
	baseline := model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"ok":true}`)}
	newContext := func(mode string) (*Context, *int) {
		ctx := testContext(t, "GET /query?id=1 HTTP/1.1\r\nHost: bank.test\r\n\r\n", baseline)
		ctx.Mode = mode
		sends := 0
		ctx.SendFunc = func(_ context.Context, _ *httpraw.Request) (model.Response, error) {
			sends++
			return baseline, nil
		}
		return ctx, &sends
	}
	normalSQL, normalSQLSends := newContext("normal")
	if _, err := (SQLInjection{}).Scan(normalSQL); err != nil {
		t.Fatal(err)
	}
	standardSQL, standardSQLSends := newContext("standard")
	if _, err := (SQLInjection{}).Scan(standardSQL); err != nil {
		t.Fatal(err)
	}
	if *normalSQLSends != 5 || *standardSQLSends != 5 {
		t.Fatalf("unexpected SQL request counts: normal=%d standard=%d", *normalSQLSends, *standardSQLSends)
	}

	normalError, normalErrorSends := newContext("normal")
	if _, err := (ErrorDisclosure{}).Scan(normalError); err != nil {
		t.Fatal(err)
	}
	standardError, standardErrorSends := newContext("standard")
	if _, err := (ErrorDisclosure{}).Scan(standardError); err != nil {
		t.Fatal(err)
	}
	if *normalErrorSends != 1 || *standardErrorSends != 1 {
		t.Fatalf("unexpected error-disclosure probe counts: normal=%d standard=%d", *normalErrorSends, *standardErrorSends)
	}
}

func TestSQLQuoteBreakAndDoubleQuoteRepairDifferential(t *testing.T) {
	baseline := model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"code":200,"rows":[{"time":"20260722","amount":731}],"message":"success"}`)}
	ctx := testContext(t, "GET /query?queryStartTime=20260722 HTTP/1.1\r\nHost: bank.test\r\n\r\n", baseline)
	ctx.Baselines = []model.Response{baseline, baseline}
	sends := 0
	ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
		sends++
		parsed, _ := url.Parse(request.Target)
		value := parsed.Query().Get("queryStartTime")
		if strings.HasSuffix(value, "'") && !strings.HasSuffix(value, "''") {
			return model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"code":400,"rows":[],"message":"数据为空"}`)}, nil
		}
		return baseline, nil
	}
	findings, err := (SQLInjection{}).Scan(ctx)
	if err != nil || len(findings) != 1 || sends != 25 {
		t.Fatalf("quote break/repair differential was not confirmed: sends=%d err=%v findings=%+v", sends, err, findings)
	}
	if findings[0].Title != "疑似 SQL 字符串边界可控" ||
		findings[0].Severity != model.SeverityHigh ||
		findings[0].Confidence != model.ConfidenceFirm {
		t.Fatalf("unexpected quote differential classification: %#v", findings[0])
	}
}

func TestSQLConditionalErrorPairAfterQuoteRecovery(t *testing.T) {
	baseline := model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"code":200,"rows":[731]}`)}
	ctx := testContext(t, "GET /query?queryStartTime=20260722 HTTP/1.1\r\nHost: bank.test\r\n\r\n", baseline)
	ctx.Baselines = []model.Response{baseline, baseline}
	sends := 0
	ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
		sends++
		parsed, _ := url.Parse(request.Target)
		value := parsed.Query().Get("queryStartTime")
		switch {
		case strings.Contains(value, "CASE WHEN 1=2"):
			return model.Response{StatusCode: 500, Headers: jsonHeader(), Body: []byte(`{"code":500,"message":"numeric value out of range"}`)}, nil
		case strings.Contains(value, "CASE WHEN 1=1"):
			return baseline, nil
		case strings.HasSuffix(value, "'") && !strings.HasSuffix(value, "''"):
			return model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"code":400,"rows":[]}`)}, nil
		default:
			return baseline, nil
		}
	}
	findings, err := (SQLInjection{}).Scan(ctx)
	if err != nil || len(findings) != 1 || sends != 9 {
		t.Fatalf("conditional error oracle was not confirmed: sends=%d err=%v findings=%+v", sends, err, findings)
	}
	if findings[0].Title != "SQL 条件错误差分注入" || findings[0].Confidence != model.ConfidenceFirm {
		t.Fatalf("unexpected conditional error classification: %#v", findings[0])
	}
}

func TestSQLConcatEmptyRecoveryAndConditionalError(t *testing.T) {
	baseline := model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"code":200,"rows":[{"app":"F-FMTA"}],"message":"success"}`)}
	ctx := testContext(t, "POST /query HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/json\r\n\r\n{\"app\":\"F-FMTA\"}", baseline)
	ctx.Baselines = []model.Response{baseline, baseline}
	sends := 0
	ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
		sends++
		body := string(request.Body)
		switch {
		case strings.Contains(body, "CASE WHEN 1=2"):
			return model.Response{StatusCode: 500, Headers: jsonHeader(), Body: []byte(`{"code":500,"message":"numeric value out of range"}`)}, nil
		case strings.Contains(body, "CASE WHEN 1=1"):
			return baseline, nil
		case strings.Contains(body, `'||''||'`):
			return baseline, nil
		case strings.Contains(body, `F-FMTA'`):
			return model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"code":200,"rows":[]}`)}, nil
		default:
			return baseline, nil
		}
	}
	findings, err := (SQLInjection{}).Scan(ctx)
	if err != nil || len(findings) != 1 || sends != 13 {
		t.Fatalf("concat-empty recovery oracle was not confirmed: sends=%d err=%v findings=%+v", sends, err, findings)
	}
	if findings[0].Title != "SQL 条件错误差分注入" || findings[0].Confidence != model.ConfidenceFirm {
		t.Fatalf("unexpected concat conditional classification: %#v", findings[0])
	}
}

func TestSQLEmptyJSONStringUsesOriginalValueAndBusinessCodeOracle(t *testing.T) {
	baseline := model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"code":0,"data":[{"row":1},{"row":2},{"row":3}],"message":"success"}`)}
	ctx := testContext(t, "POST /query HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/json\r\n\r\n{\"query\":\"\"}", baseline)
	ctx.Baselines = []model.Response{baseline, baseline}
	var bodies []string
	ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
		body := string(request.Body)
		bodies = append(bodies, body)
		switch {
		case strings.Contains(body, "CASE WHEN 1=2"):
			return model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"code":-3,"message":"系统处理异常"}`)}, nil
		case strings.Contains(body, "CASE WHEN 1=1"):
			return model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"code":0,"message":"success"}`)}, nil
		case strings.Contains(body, `"query":"'"`):
			return model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"code":-3,"message":"系统处理异常"}`)}, nil
		case strings.Contains(body, `"query":"''"`):
			return model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"code":0,"message":"success"}`)}, nil
		default:
			return baseline, nil
		}
	}
	findings, err := (SQLInjection{}).Scan(ctx)
	if err != nil || len(findings) != 1 || findings[0].Title != "SQL 条件错误差分注入" {
		t.Fatalf("empty JSON SQL oracle was missed: err=%v findings=%+v bodies=%q", err, findings, bodies)
	}
	allBodies := strings.Join(bodies, "\n")
	if strings.Contains(allBodies, `"query":"1'`) ||
		!strings.Contains(allBodies, `"query":"'"`) ||
		!strings.Contains(allBodies, `"query":"''"`) ||
		!strings.Contains(allBodies, `"query":"' AND (CASE WHEN`) {
		t.Fatalf("empty value or PostgreSQL/GaussDB concat context was not preserved: %s", allBodies)
	}
}

func TestSQLQuoteRecoveryAcceptsGenericWrapped500(t *testing.T) {
	baseline := model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"code":200,"data":[731]}`)}
	ctx := testContext(t, "GET /query?queryStartTime=20260722 HTTP/1.1\r\nHost: bank.test\r\n\r\n", baseline)
	ctx.Baselines = []model.Response{baseline, baseline}
	ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
		parsed, _ := url.Parse(request.Target)
		value := parsed.Query().Get("queryStartTime")
		if strings.HasSuffix(value, "'") && !strings.HasSuffix(value, "''") {
			return model.Response{StatusCode: 500, Headers: jsonHeader(), Body: []byte(`{"code":500,"message":"系统繁忙"}`)}, nil
		}
		return baseline, nil
	}
	findings, err := (SQLInjection{}).Scan(ctx)
	if err != nil || len(findings) != 1 || findings[0].Title != "疑似 SQL 字符串边界可控" ||
		findings[0].Severity != model.SeverityHigh {
		t.Fatalf("wrapped 500 quote recovery was not detected: err=%v findings=%+v", err, findings)
	}
}

func TestMultipartJSPXUploadWithRenamedFilename(t *testing.T) {
	body := "---xxxxxx\r\n" +
		"Content-Disposition: form-data;name=\"1.txt\"; filename=\"1.txt\"\r\n" +
		"Content-Type: application/octet-stream\r\n\r\n" +
		"safe\r\n---xxxxxx--\r\n"
	raw := "POST /xxxx/servlet/UploadLoanPhotoServlet HTTP/1.1\r\nHost: bank.test\r\nContent-Type: multipart/form-data; boundary=-xxxxxx\r\n\r\n" + body
	baseline := model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"filename":"202607240001.txt"}`)}
	ctx := testContext(t, raw, baseline)
	ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
		requestBody := string(request.Body)
		switch {
		case strings.Contains(requestBody, ".jspx"):
			return model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"filename":"202607240731.jspx"}`)}, nil
		case strings.Contains(requestBody, ".jsp"):
			return model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"errorString":"UploadFileTypeNot"}`)}, nil
		default:
			return baseline, nil
		}
	}
	findings, err := (FileUpload{}).Scan(ctx)
	if err != nil || len(findings) != 1 {
		t.Fatalf("renamed JSPX upload acceptance was missed: err=%v findings=%+v", err, findings)
	}
	if !strings.Contains(findings[0].Title, ".jspx") || findings[0].Confidence != model.ConfidenceFirm {
		t.Fatalf("unexpected renamed JSPX upload classification: %#v", findings[0])
	}
}

func TestSQLQuoteRepairDetectsSmallStableDifferenceInLongJSP(t *testing.T) {
	prefix := "<html><body>" + strings.Repeat("<div>normal business content 731</div>", 500)
	baseline := model.Response{StatusCode: 200, Headers: map[string]string{"content-type": "text/html; charset=UTF-8"}, Body: []byte(prefix + "<span>查询成功</span></body></html>")}
	broken := model.Response{StatusCode: 200, Headers: baseline.Headers, Body: []byte(prefix + "<span>查询为空</span></body></html>")}
	ctx := testContext(t, "GET /query?queryStartTime=20260722 HTTP/1.1\r\nHost: bank.test\r\n\r\n", baseline)
	ctx.Baselines = []model.Response{baseline, baseline}
	sends := 0
	ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
		sends++
		parsed, _ := url.Parse(request.Target)
		value := parsed.Query().Get("queryStartTime")
		if strings.HasSuffix(value, "'") && !strings.HasSuffix(value, "''") {
			return broken, nil
		}
		return baseline, nil
	}
	findings, err := (SQLInjection{}).Scan(ctx)
	if err != nil || len(findings) != 1 || sends != 25 || findings[0].Title != "疑似 SQL 字符串边界可控" {
		t.Fatalf("stable subtle JSP differential was missed: sends=%d err=%v findings=%+v", sends, err, findings)
	}
}

func TestSQLStopsEscalatingAfterConfirmedErrorSignal(t *testing.T) {
	baseline := model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"ok":true}`)}
	ctx := testContext(t, "GET /query?id=1 HTTP/1.1\r\nHost: bank.test\r\n\r\n", baseline)
	ctx.Mode = "standard"
	sends := 0
	ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
		sends++
		parsed, _ := url.Parse(request.Target)
		value := parsed.Query().Get("id")
		if strings.HasSuffix(value, "'") && !strings.HasSuffix(value, "''") {
			return model.Response{StatusCode: 500, Headers: jsonHeader(), Body: []byte("org.postgresql.util.PSQLException: unterminated quoted string")}, nil
		}
		return baseline, nil
	}
	findings, err := (SQLInjection{}).Scan(ctx)
	if err != nil || len(findings) != 1 || sends != 5 {
		t.Fatalf("confirmed SQL error should stop boolean/time escalation: sends=%d err=%v findings=%+v", sends, err, findings)
	}
}

func TestV2RegistryAndDefaultRuleCoverage(t *testing.T) {
	if len(All()) != 52 {
		t.Fatalf("expected exactly 52 registered plugins, got %d", len(All()))
	}
	cfg := config.Default()
	for _, id := range []string{"unauthorized", "sqli", "sqli_extended", "sqli_timing", "sqli_order_by", "sqli_limit", "xxe", "xxe_extended", "file_read", "file_read_encoded", "file_upload", "file_upload_execution", "cors", "reflected_xss", "ssrf", "open_redirect", "crlf_injection", "ssti", "command_injection", "command_injection_oast", "command_injection_timing", "csrf", "error_disclosure", "error_disclosure_extended", "nosql_injection", "ldap_injection", "xpath_injection", "java_deserialization", "method_override", "mass_assignment", "mass_assignment_extended", "mybatis_dynamic_sql", "json_polymorphic", "graphql_security", "graphql_alias_abuse", "sms_abuse", "shiro", "java_expression", "java_expression_extended", "jndi_injection", "host_header_injection"} {
		if len(cfg.PluginRules[id].Payloads) == 0 {
			t.Fatalf("payload-driven plugin %s has no Web-configurable defaults", id)
		}
	}
	if len(cfg.PluginRules["sensitive_data"].Patterns) == 0 || len(cfg.PluginRules["sqli"].Patterns) == 0 {
		t.Fatal("detection regex defaults are missing")
	}
}

func TestScanPresets(t *testing.T) {
	passive, err := PresetIDs("passive")
	if err != nil {
		t.Fatal(err)
	}
	normal, err := PresetIDs("normal")
	if err != nil {
		t.Fatal(err)
	}
	deep, err := PresetIDs("deep")
	if err != nil {
		t.Fatal(err)
	}
	if len(passive) != 3 || len(normal) != 9 || len(deep) != 52 {
		t.Fatalf("unexpected preset sizes: passive=%d normal=%d deep=%d", len(passive), len(normal), len(deep))
	}
	for _, required := range []string{"sqli", "sqli_extended", "file_upload", "file_read", "reflected_xss", "unauthorized", "xxe", "sms_abuse", "sensitive_data"} {
		if !contains(normal, required) {
			t.Fatalf("normal preset missing %s: %#v", required, normal)
		}
	}
	selected, err := Select([]string{"sqli_timing"}, "passive")
	if err != nil || len(selected) != 1 || selected[0].Meta().ID != "sqli_timing" {
		t.Fatalf("explicit plugin selection must not be filtered by compatibility mode: selected=%#v err=%v", selected, err)
	}
}

func TestPresetIDsWithNormalUsesConfiguredPlugins(t *testing.T) {
	ids, err := PresetIDsWithNormal("normal", []string{"sqli_timing", "jwt_weak"})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(ids, "sqli_timing") || !contains(ids, "jwt_weak") || contains(ids, "sqli") {
		t.Fatalf("configured normal preset was not applied: %#v", ids)
	}
	empty, err := PresetIDsWithNormal("normal", []string{})
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty configured normal preset was not retained: ids=%#v err=%v", empty, err)
	}
}

func TestExplicitPluginSelectionIgnoresCompatibilityMode(t *testing.T) {
	for _, mode := range []string{"passive", "normal", "standard", "deep"} {
		selected, err := Select([]string{"sqli", "sqli_timing"}, mode)
		if err != nil || len(selected) != 2 {
			t.Fatalf("mode %s changed explicit plugin selection: selected=%d err=%v", mode, len(selected), err)
		}
	}
}

func TestAuthorizationAndV2Plugins(t *testing.T) {
	t.Run("command-injection-canary", func(t *testing.T) {
		ctx := testContext(t, "GET /ping?host=127.0.0.1 HTTP/1.1\r\nHost: bank.test\r\n\r\n", model.Response{StatusCode: 200, Headers: map[string]string{"content-type": "text/plain"}, Body: []byte("pong")})
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			u, _ := url.Parse(request.Target)
			value := u.Query().Get("host")
			body := "pong"
			match := regexp.MustCompile(`\$\(\((\d+)\+(\d+)\)\)`).FindStringSubmatch(value)
			if len(match) == 3 {
				left, _ := strconv.ParseInt(match[1], 10, 64)
				right, _ := strconv.ParseInt(match[2], 10, 64)
				body += fmt.Sprintf("JHS_%d", left+right)
			}
			return model.Response{StatusCode: 200, Headers: map[string]string{"content-type": "text/plain"}, Body: []byte(body)}, nil
		}
		findings, err := (CommandInjection{}).Scan(ctx)
		assertFinding(t, findings, err, "command_injection")
	})

	t.Run("command-injection-reflection-is-not-execution", func(t *testing.T) {
		ctx := testContext(t, "GET /ping?host=127.0.0.1 HTTP/1.1\r\nHost: bank.test\r\n\r\n", model.Response{StatusCode: 200, Headers: map[string]string{"content-type": "text/plain"}, Body: []byte("pong")})
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			u, _ := url.Parse(request.Target)
			return model.Response{StatusCode: 200, Headers: map[string]string{"content-type": "text/plain"}, Body: []byte("echo:" + u.Query().Get("host"))}, nil
		}
		findings, err := (CommandInjection{}).Scan(ctx)
		if err != nil || len(findings) != 0 {
			t.Fatalf("reflected command payload must not be treated as execution: findings=%#v err=%v", findings, err)
		}
	})

	t.Run("command-injection-offline-callback", func(t *testing.T) {
		ctx := testContext(t, "GET /ping?host=127.0.0.1 HTTP/1.1\r\nHost: bank.test\r\n\r\n", model.Response{StatusCode: 200, Headers: map[string]string{"content-type": "text/plain"}, Body: []byte("pong")})
		ctx.Mode = "deep"
		ctx.Config.CallbackBaseURL = "http://127.0.0.1:61166"
		rule := ctx.Config.PluginRules["command_injection"]
		rule.Payloads = []config.PayloadRule{{Name: "curl callback", Kind: "callback", Payload: "{{value}};curl '{{callback}}'", Mode: "deep"}}
		ctx.Config.PluginRules["command_injection"] = rule
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			u, _ := url.Parse(request.Target)
			value := u.Query().Get("host")
			marker := "/api/v1/callback/"
			if at := strings.Index(value, marker); at >= 0 {
				token := strings.Trim(strings.Fields(value[at+len(marker):])[0], "'\"")
				ctx.Callbacks.Hit(token)
			}
			return ctx.Baseline, nil
		}
		findings, err := (CommandInjection{}).Scan(ctx)
		assertFinding(t, findings, err, "command_injection")
	})

	t.Run("csrf", func(t *testing.T) {
		ctx := testContext(t, "POST /transfer HTTP/1.1\r\nHost: bank.test\r\nCookie: JSESSIONID=secret\r\nContent-Type: application/json\r\nX-CSRF-Token: abc\r\n\r\n{\"amount\":1}", model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"code":"000000","message":"success"}`)})
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			if request.Header("X-CSRF-Token") != "" || request.Header("Origin") != "https://jungle-happy-scan.invalid" {
				t.Fatalf("CSRF mutation not applied")
			}
			return ctx.Baseline, nil
		}
		findings, err := (CSRF{}).Scan(ctx)
		assertFinding(t, findings, err, "csrf")
	})

	t.Run("api-exposure", func(t *testing.T) {
		ctx := testContext(t, "GET / HTTP/1.1\r\nHost: bank.test\r\nCookie: JSESSIONID=secret\r\n\r\n", model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"code":"000000"}`)})
		rule := ctx.Config.PluginRules["api_exposure"]
		rule.Paths = []string{"/v3/api-docs"}
		ctx.Config.PluginRules["api_exposure"] = rule
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			if request.Target != "/v3/api-docs" || request.Header("Cookie") != "" {
				t.Fatalf("API exposure request not anonymous: %#v", request)
			}
			return model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"openapi":"3.0.1","paths":{"/users":{}}}`)}, nil
		}
		findings, err := (APIExposure{}).Scan(ctx)
		assertFinding(t, findings, err, "api_exposure")
	})
}

func testContext(t *testing.T, raw string, baseline model.Response) *Context {
	t.Helper()
	cfg := config.Default()
	cfg.BaselineSamples = 1
	request, err := httpraw.Parse(raw, "https")
	if err != nil {
		t.Fatal(err)
	}
	return &Context{
		Context: context.Background(), Request: request, Baselines: []model.Response{baseline}, Baseline: baseline,
		Points: httpraw.Discover(request, false), Mode: "standard", Config: cfg, Callbacks: callback.New(),
		SendFunc: func(context.Context, *httpraw.Request) (model.Response, error) {
			return model.Response{}, fmt.Errorf("send not configured")
		},
		Progress: func(string, int, int) {},
	}
}

func assertFinding(t *testing.T, findings []model.Finding, err error, pluginID string) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 || findings[0].PluginID != pluginID {
		t.Fatalf("expected %s finding, got %#v", pluginID, findings)
	}
}

func TestEvidenceStrengthRequiresConfirmedCallbackForL5(t *testing.T) {
	if got := evidenceStrength(map[string]any{"callback_token": "reflected-only"}); got == "L5" {
		t.Fatalf("unconfirmed callback token must not be L5, got %q", got)
	}
	if got := evidenceStrength(map[string]any{"callback": true, "callback_token": "one-time-token"}); got != "L5" {
		t.Fatalf("confirmed callback evidence strength = %q, want L5", got)
	}
	if got := evidenceStrength(map[string]any{"evidence_strength": "L4", "match": "x"}); got != "L4" {
		t.Fatalf("explicit evidence strength = %q, want L4", got)
	}
}

func jsonHeader() map[string]string { return map[string]string{"content-type": "application/json"} }
func htmlHeader() map[string]string {
	return map[string]string{"content-type": "text/html; charset=utf-8"}
}
