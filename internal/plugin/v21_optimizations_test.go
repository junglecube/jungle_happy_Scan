package plugin

import (
	"context"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

func TestSQLPointsExcludeCookieAndHeaders(t *testing.T) {
	points := []httpraw.InsertionPoint{
		{Location: "query", Name: "query", Value: "value"},
		{Location: "cookie", Name: "session", Value: "value"},
		{Location: "header", Name: "X-Trace", Value: "value"},
	}
	got := prioritizeSQLPoints(points)
	if len(got) != 1 || got[0].Location != "query" {
		t.Fatalf("SQL points should exclude cookie and headers, got %#v", got)
	}
}

func TestSQLV21PriorityContextAndBestEvidence(t *testing.T) {
	points := []httpraw.InsertionPoint{
		{Location: "header", Name: "User-Agent", Value: "browser", ValueType: "string"},
		{Location: "json", Name: "queryStartTime", Value: "20260722", ValueType: "string"},
		{Location: "json", Name: "amount", Value: "731", ValueType: "number"},
	}
	ordered := prioritizeSQLPoints(points)
	if ordered[0].Name != "amount" && ordered[0].Name != "queryStartTime" {
		t.Fatalf("business SQL point should outrank header, got %#v", ordered)
	}
	for _, point := range ordered {
		if point.Location == "cookie" || point.Location == "header" {
			t.Fatalf("ambient request metadata should be excluded, got %#v", ordered)
		}
	}
	if got := classifySQLContext(points[1]); got != "date-string" {
		t.Fatalf("date string context = %q", got)
	}
	if got := classifySQLContext(points[2]); got != "numeric" {
		t.Fatalf("typed number context = %q", got)
	}

	rules := []config.DetectionRule{
		{Name: "通用异常", Pattern: `(?i)error`, Severity: "medium", Confidence: "firm"},
		{Name: "MySQL/JDBC 异常", Pattern: `(?i)MySQLSyntaxErrorException`, Severity: "high", Confidence: "certain"},
	}
	match := bestPatternRule(compileDetectionPatterns(rules), []byte("error MySQLSyntaxErrorException"))
	if match.name != "MySQL/JDBC 异常" {
		t.Fatalf("best SQL evidence = %#v", match)
	}
}

func TestSQLV21MySQLConditionalErrorConfirmation(t *testing.T) {
	baseline := model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"code":200,"rows":[{"app":"F-FMTA"}]}`)}
	ctx := testContext(t, "POST /query HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/json\r\n\r\n{\"app\":\"F-FMTA\"}", baseline)
	ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
		body := string(request.Body)
		switch {
		case strings.Contains(body, "CASE WHEN 1=2"):
			return model.Response{StatusCode: 500, Headers: jsonHeader(), Body: []byte("java.sql.SQLException: DOUBLE value is out of range in 'exp(720)'")}, nil
		case strings.Contains(body, "CASE WHEN 1=1"), strings.Contains(body, `'||''||'`):
			return baseline, nil
		case strings.Contains(body, `F-FMTA'`):
			return model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"code":400,"rows":[]}`)}, nil
		default:
			return baseline, nil
		}
	}
	findings, err := (SQLInjection{}).Scan(ctx)
	assertFinding(t, findings, err, "sqli")
	if findings[0].Title != "SQL 条件错误差分注入" {
		t.Fatalf("unexpected SQL title %q", findings[0].Title)
	}
}

func TestFileUploadV21ScansEveryMultipartFileField(t *testing.T) {
	raw := "POST /upload HTTP/1.1\r\nHost: bank.test\r\nContent-Type: multipart/form-data; boundary=abc\r\n\r\n" +
		"--abc\r\nContent-Disposition: form-data; name=\"cover\"; filename=\"cover.txt\"\r\nContent-Type: text/plain\r\n\r\ncover\r\n" +
		"--abc\r\nContent-Disposition: form-data; name=\"attachment\"; filename=\"report.txt\"\r\nContent-Type: text/plain\r\n\r\nreport\r\n--abc--\r\n"
	baseline := model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"code":400}`)}
	ctx := testContext(t, raw, baseline)
	ctx.Config.PluginRules["file_upload"] = config.PluginRuleConfig{Payloads: []config.PayloadRule{{
		Name: "JSPX", Payload: "jhs.jspx", Mime: "application/octet-stream",
		Expected: `(?i)上传成功`,
	}}}
	ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
		files := request.MultipartFiles()
		if len(files) == 2 && files[1].Filename == "jhs.jspx" {
			return model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"filename":"renamed.jspx","message":"上传成功"}`)}, nil
		}
		return baseline, nil
	}
	findings, err := (FileUpload{}).Scan(ctx)
	assertFinding(t, findings, err, "file_upload")
	if !strings.Contains(findings[0].Affected, "attachment") {
		t.Fatalf("finding must identify second file field: %#v", findings[0])
	}
}

func TestFileUploadV21LegacyServletLeadingHyphenBoundary(t *testing.T) {
	const boundary = "-ZNd1WHmZirZ1vuRrBwPACLW29XMkLNZGE"
	body := "--" + boundary + "\n" +
		"Content-Disposition: form-data; name=\"020079103915427_0.jpg\"; filename=\"020079103915427_0.jpg\"\n" +
		"Content-Type: application/octet-stream\n" +
		"Content-Transfer-Encoding: binary\n\n" +
		"1234\n--" + boundary + "--\n"
	raw := "POST /ICBCWAPBankB7EBT/servlet/UploadLoanPhotoServlet HTTP/1.1\r\n" +
		"Host: bank.test:10790\r\n" +
		"Content-Type: multipart/form-data; boundary=" + boundary + "\r\n\r\n" + body
	baseline := model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`filename：“20260724161953.jpg”`)}
	ctx := testContext(t, raw, baseline)
	ctx.Config.PluginRules["file_upload"] = config.Default().PluginRules["file_upload"]
	ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
		files := request.MultipartFiles()
		if len(files) != 1 {
			t.Fatalf("mutated multipart files = %#v\n%s", files, request.Raw(false))
		}
		if !strings.Contains(string(request.Body), "\r\n\r\n1234\r\n") {
			return model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`errorString：UploadFileContentNot`)}, nil
		}
		// This legacy Servlet incorrectly validates the field name rather than
		// the standard filename parameter.
		switch strings.ToLower(filepath.Ext(files[0].FieldName)) {
		case ".jsp":
			return model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`errorString：UploadFileTypeNot`)}, nil
		case ".jspx":
			return model.Response{StatusCode: 500, Headers: jsonHeader(), Body: []byte(`{"message":"{\"filename\":\"202607241731.jspx\"}"}`)}, nil
		default:
			return baseline, nil
		}
	}
	findings, err := (FileUpload{}).Scan(ctx)
	assertFinding(t, findings, err, "file_upload")
	if !strings.Contains(findings[0].Title, ".jspx") {
		t.Fatalf("JSPX acceptance was not selected: %#v", findings)
	}
	if findings[0].Evidence[0].Metrics["legacy_field_name_mutation"] != true {
		t.Fatalf("legacy field-name compatibility path was not used: %#v", findings[0].Evidence)
	}
	if findings[0].Evidence[0].Metrics["original_content_preserved"] != true {
		t.Fatalf("ordinary extension probe did not preserve original content: %#v", findings[0].Evidence)
	}
}

func TestReflectedXSSV21RejectsInertContextsAndFindsAttribute(t *testing.T) {
	t.Run("comment-is-inert", func(t *testing.T) {
		ctx := testContext(t, "GET /search?q=hello HTTP/1.1\r\nHost: bank.test\r\n\r\n", model.Response{StatusCode: 200, Headers: htmlHeader(), Body: []byte("<html></html>")})
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			parsed, _ := url.Parse(request.Target)
			return model.Response{StatusCode: 200, Headers: htmlHeader(), Body: []byte("<html><!--" + parsed.Query().Get("q") + "--></html>")}, nil
		}
		findings, err := (ReflectedXSS{}).Scan(ctx)
		if err != nil || len(findings) != 0 {
			t.Fatalf("HTML comment reflection must not alert: findings=%#v err=%v", findings, err)
		}
	})

	t.Run("quoted-attribute", func(t *testing.T) {
		ctx := testContext(t, "GET /search?q=hello HTTP/1.1\r\nHost: bank.test\r\n\r\n", model.Response{StatusCode: 200, Headers: htmlHeader(), Body: []byte(`<html><input value="hello"></html>`)})
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			parsed, _ := url.Parse(request.Target)
			return model.Response{StatusCode: 200, Headers: htmlHeader(), Body: []byte(`<html><input value="` + parsed.Query().Get("q") + `"></html>`)}, nil
		}
		findings, err := (ReflectedXSS{}).Scan(ctx)
		assertFinding(t, findings, err, "reflected_xss")
		if findings[0].Evidence[0].Metrics["context"] != "attribute-double" {
			t.Fatalf("attribute context not retained: %#v", findings[0].Evidence)
		}
	})

	t.Run("single-quoted-attribute", func(t *testing.T) {
		ctx := testContext(t, "GET /search?q=hello HTTP/1.1\r\nHost: bank.test\r\n\r\n", model.Response{StatusCode: 200, Headers: htmlHeader(), Body: []byte(`<html><input value='hello'></html>`)})
		ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
			parsed, _ := url.Parse(request.Target)
			return model.Response{StatusCode: 200, Headers: htmlHeader(), Body: []byte(`<html><input value='` + parsed.Query().Get("q") + `'></html>`)}, nil
		}
		findings, err := (ReflectedXSS{}).Scan(ctx)
		assertFinding(t, findings, err, "reflected_xss")
		if findings[0].Evidence[0].Metrics["context"] != "attribute-single" {
			t.Fatalf("single-quoted context not retained: %#v", findings[0].Evidence)
		}
	})
}

func TestResponseHeaderValuesPreserveRepeatedSetCookie(t *testing.T) {
	response := model.Response{
		Headers: map[string]string{"set-cookie": "a=1, b=2"},
		HeaderValues: map[string][]string{"set-cookie": {
			"a=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT",
			"rememberMe=deleteMe; Path=/",
		}},
	}
	values := response.HeaderAll("Set-Cookie")
	if len(values) != 2 || !shiroDeleteMe(response) {
		t.Fatalf("repeated Set-Cookie lost: %#v", values)
	}
}

func TestSecurityHeadersV21ValidatesValuesAndSessionCookies(t *testing.T) {
	baseline := model.Response{
		StatusCode: 200,
		Headers: map[string]string{
			"content-type":            "text/html",
			"content-security-policy": "default-src 'self'; frame-ancestors 'self'",
			"x-frame-options":         "ALLOWALL",
			"x-content-type-options":  "nosniff",
		},
		HeaderValues: map[string][]string{
			"set-cookie": {
				"JSESSIONID=731; Path=/",
				"theme=light; Path=/",
			},
		},
		Body: []byte("<html><body>ok</body></html>"),
	}
	ctx := testContext(t, "GET / HTTP/1.1\r\nHost: bank.test\r\n\r\n", baseline)
	ctx.Request.Scheme = "https"
	findings, err := (SecurityHeaders{}).Scan(ctx)
	if err != nil || len(findings) != 2 {
		t.Fatalf("security header/cookie findings = %#v err=%v", findings, err)
	}
	if findings[1].Title != "会话 Cookie 缺少安全属性" {
		t.Fatalf("session cookie issue missing: %#v", findings)
	}

	jsonBaseline := baseline
	jsonBaseline.Headers = map[string]string{"content-type": "application/json"}
	jsonBaseline.Body = []byte(`{"ok":true}`)
	jsonContext := testContext(t, "GET /api/me HTTP/1.1\r\nHost: bank.test\r\n\r\n", jsonBaseline)
	jsonContext.Request.Scheme = "https"
	jsonFindings, err := (SecurityHeaders{}).Scan(jsonContext)
	if err != nil || len(jsonFindings) != 1 || jsonFindings[0].Title != "会话 Cookie 缺少安全属性" {
		t.Fatalf("JSON Set-Cookie must still be checked: %#v err=%v", jsonFindings, err)
	}
}
