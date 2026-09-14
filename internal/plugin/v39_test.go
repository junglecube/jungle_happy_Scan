package plugin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"html"
	"io"
	"jungle_happy_Scan/internal/callback"
	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestV39SMSWholeDecisionAndConfiguredPool(t *testing.T) {
	ctx := testContext(t, "POST /send?mobile=13812345678 HTTP/1.1\r\nHost: bank.test\r\n\r\n", model.Response{StatusCode: 200})
	patterns := compileDetectionPatterns(ctx.Rule("sms_abuse").Patterns)
	for _, body := range []string{`{"code":200,"success":false,"msg":"发送失败，请稍后重试"}`, `{"code":0,"message":"请求频繁"}`, `{"message":"unknown"}`} {
		if smsResponseSuccess(model.Response{StatusCode: 200, Body: []byte(body)}, ctx, patterns) {
			t.Fatalf("false success: %s", body)
		}
	}
	rules := []config.PayloadRule{{Kind: "spray_number", Payload: "13800000001"}}
	requests, _ := smsSprayRequests(ctx, ctx.Points[0], rules)
	if len(requests) != 1 {
		t.Fatalf("implicit expansion: %d", len(requests))
	}
	requests, _ = smsSprayRequests(ctx, ctx.Points[0], nil)
	if len(requests) != 0 {
		t.Fatal("empty pool sent requests")
	}
}
func TestV39XXEDeclarationCDATAAndReflection(t *testing.T) {
	for _, cdata := range []bool{false, true} {
		inner := "original"
		if cdata {
			inner = "<![CDATA[original]]>"
		}
		ctx := testContext(t, "POST /xml HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/xml\r\n\r\n<?xml version=\"1.0\"?><root><value>"+inner+"</value></root>", model.Response{StatusCode: 200})
		rule := ctx.Rule("xxe")
		rule.Payloads = rule.Payloads[:1]
		ctx.Config.PluginRules["xxe"] = rule
		ctx.SendFunc = func(_ context.Context, r *httpraw.Request) (model.Response, error) {
			body := string(r.Body)
			if strings.Count(body, "<?xml") != 1 || strings.Contains(body, "<![CDATA[") {
				t.Fatalf("invalid constructed XML: %s", body)
			}
			// Parse entity definition text using the standard XML character decoder.
			re := regexp.MustCompile(`<!ENTITY jungle_happy_scan "([^"]+)">`)
			m := re.FindStringSubmatch(body)
			if len(m) != 2 {
				t.Fatal(body)
			}
			dec := xml.NewDecoder(strings.NewReader("<v>" + m[1] + "</v>"))
			out := ""
			for {
				tok, err := dec.Token()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if text, ok := tok.(xml.CharData); ok {
					out += string(text)
				}
			}
			return model.Response{StatusCode: 200, Body: []byte(out)}, nil
		}
		got, err := (XXE{}).Scan(ctx)
		if err != nil || len(got) != 1 {
			t.Fatalf("entity not detected: %d %v", len(got), err)
		}
		ctx.SendFunc = func(_ context.Context, r *httpraw.Request) (model.Response, error) {
			return model.Response{StatusCode: 200, Body: r.Body}, nil
		}
		got, err = (XXE{}).Scan(ctx)
		if err != nil || len(got) != 0 {
			t.Fatal("raw XML reflection mistaken for entity expansion")
		}
	}
}
func TestV39FileReadDecodedContentAndNegativeControl(t *testing.T) {
	for _, fixed := range []bool{false, true} {
		ctx := testContext(t, "GET /download?opaque=docs/report.pdf HTTP/1.1\r\nHost: bank.test\r\n\r\n", model.Response{StatusCode: 200, Body: []byte("baseline")})
		ctx.Config.PluginRules["file_read"] = config.PluginRuleConfig{Payloads: []config.PayloadRule{{Name: "file", Payload: "/etc/passwd", Expected: `(?m)^root:x:0:0:`}}}
		ctx.SendFunc = func(_ context.Context, r *httpraw.Request) (model.Response, error) {
			u, _ := url.Parse(r.Target)
			text := "missing"
			if fixed || u.Query().Get("opaque") == "/etc/passwd" {
				text = base64.StdEncoding.EncodeToString([]byte("root:x:0:0:root:/root:/bin/bash\n"))
			}
			body, _ := json.Marshal(map[string]string{"content": text})
			return model.Response{StatusCode: 200, Body: body}, nil
		}
		got, err := (FileRead{}).Scan(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if fixed && len(got) != 0 {
			t.Fatal("fixed diagnostic page confirmed")
		}
		if !fixed && (len(got) != 1 || len(got[0].Evidence) != 3) {
			t.Fatal("decoded file with negative control not detected")
		}
	}
}
func TestV39UploadDecisions(t *testing.T) {
	ctx := testContext(t, "GET / HTTP/1.1\r\nHost: bank.test\r\n\r\n", model.Response{StatusCode: 200, Body: []byte(`{"code":0}`)})
	for _, tt := range []struct {
		body string
		want bool
	}{{`{"code":0}`, true}, {`{"path":"/uploads/item.jsp"}`, false}, {`{"filename":"probe.jsp","success":false}`, false}, {`{"message":"probe.jsp"}`, false}} {
		_, _, got := uploadAccepted(ctx, model.Response{StatusCode: 200, Body: []byte(tt.body)}, "probe.jsp", "token", false, regexp.MustCompile(`"code":0`))
		if got != tt.want {
			t.Fatalf("%s => %v", tt.body, got)
		}
	}
}
func TestV39XSSCopiesMIMEAndRawContexts(t *testing.T) {
	for _, kind := range []string{"copies", "textarea", "script-data", "mime-change", "encoded"} {
		t.Run(kind, func(t *testing.T) {
			ctx := testContext(t, "GET /?q=hello HTTP/1.1\r\nHost: bank.test\r\n\r\n", model.Response{StatusCode: 200, Headers: htmlHeader()})
			sends := 0
			ctx.SendFunc = func(_ context.Context, r *httpraw.Request) (model.Response, error) {
				sends++
				u, _ := url.Parse(r.Target)
				value := u.Query().Get("q")
				body := "<html>" + value + "<div>" + html.EscapeString(value) + "</div></html>"
				headers := htmlHeader()
				switch kind {
				case "textarea":
					body = "<html><textarea>" + value + "</textarea></html>"
				case "script-data":
					body = `<html><script type="application/json">{"value":"` + value + `"}</script></html>`
				case "mime-change":
					if sends > 1 {
						headers = jsonHeader()
					}
				case "encoded":
					body = "<html>" + html.EscapeString(value) + "</html>"
				}
				return model.Response{StatusCode: 200, Headers: headers, Body: []byte(body)}, nil
			}
			got, err := (ReflectedXSS{}).Scan(ctx)
			if err != nil {
				t.Fatal(err)
			}
			want := kind != "mime-change" && kind != "encoded"
			if (len(got) > 0) != want {
				t.Fatalf("findings=%d want %v", len(got), want)
			}
		})
	}
	if quotedAttributeDelimiter(`<input value="a\"`) != 0 {
		t.Fatal("HTML backslash escaped quote")
	}
}
func TestV39OASTSettlesOnSendErrorAndLateHit(t *testing.T) {
	for _, late := range []bool{false, true} {
		t.Run(map[bool]string{true: "late", false: "send-error"}[late], func(t *testing.T) {
			ctx := testContext(t, "GET /?url=x HTTP/1.1\r\nHost: bank.test\r\n\r\n", model.Response{StatusCode: 200})
			defer ctx.Callbacks.Close()
			ctx.Config.CallbackWaitSeconds = 0
			ctx.Config.CallbackLateSeconds = 1
			ch := make(chan []model.Finding, 1)
			ctx.OnLateFindings = func(f []model.Finding) { ch <- f }
			var token string
			ctx.SendFunc = func(_ context.Context, r *httpraw.Request) (model.Response, error) {
				token = callback.TokensFromText(r.Target)[0]
				if !late {
					ctx.Callbacks.Hit(token)
				}
				return model.Response{}, errors.New("target disconnected")
			}
			got, err := (SSRF{}).Scan(ctx)
			if err == nil {
				t.Fatal("lost transport error")
			}
			if !late {
				if len(got) != 1 {
					t.Fatal("hit lost on error")
				}
				return
			}
			ctx.Callbacks.Hit(token)
			select {
			case got = <-ch:
				if len(got) != 1 || got[0].Evidence[0].Metrics["late_callback"] != true {
					t.Fatal("late evidence missing")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("no late callback")
			}
		})
	}
}
func TestV39SensitiveValidatorSurvivesRename(t *testing.T) {
	ctx := testContext(t, "GET / HTTP/1.1\r\nHost: bank.test\r\n\r\n", model.Response{StatusCode: 200, Body: []byte("110105194912310021 11010519491231002X 11010519491231002X")})
	ctx.Config.PluginRules["sensitive_data"] = config.PluginRuleConfig{Patterns: []config.DetectionRule{{Name: "renamed", Validator: "cn_id", Pattern: `[0-9]{17}[0-9X]`}}}
	got, err := (SensitiveData{}).Scan(ctx)
	if err != nil || len(got) != 1 {
		t.Fatal("validator failed")
	}
	if got[0].Evidence[0].Metrics["match_count"] != 2 {
		t.Fatal("invalid ID included or count incorrect")
	}
}

func TestV39UploadExecutionRetainsCriticalSeverity(t *testing.T) {
	raw := "POST /upload HTTP/1.1\r\nHost: bank.test\r\nContent-Type: multipart/form-data; boundary=test\r\n\r\n--test\r\nContent-Disposition: form-data; name=\"file\"; filename=\"x.txt\"\r\n\r\noriginal\r\n--test--\r\n"
	ctx := testContext(t, raw, model.Response{StatusCode: 200, Body: []byte(`{"code":0}`)})
	ctx.Config.PluginRules["file_upload_execution"] = config.PluginRuleConfig{Payloads: []config.PayloadRule{{Name: "execute", Kind: "execute_canary", Payload: "{{token}}.jsp", Mime: "text/plain"}}}
	expected := ""
	ctx.SendFunc = func(_ context.Context, r *httpraw.Request) (model.Response, error) {
		if r.Method == "GET" {
			return model.Response{StatusCode: 200, Body: []byte(expected)}, nil
		}
		files := r.MultipartFiles()
		if len(files) != 1 {
			t.Fatal("bad multipart")
		}
		parts := regexp.MustCompile(`(\d+)\*(\d+)`).FindStringSubmatch(string(files[0].Content))
		if len(parts) != 3 {
			t.Fatal("no canary expression")
		}
		a, _ := strconv.Atoi(parts[1])
		b, _ := strconv.Atoi(parts[2])
		expected = strconv.Itoa(a * b)
		return model.Response{StatusCode: 200, Body: []byte(`{"code":0,"path":"/uploads/item.jsp"}`)}, nil
	}
	got, err := scanFileUpload(ctx, StandardMeta("file_upload_execution", "execution", "", "state-changing", true))
	if err != nil || len(got) != 1 {
		t.Fatalf("%d %v", len(got), err)
	}
	if got[0].Severity != model.SeverityCritical || got[0].Confidence != model.ConfidenceCertain {
		t.Fatal("confirmed execution downgraded")
	}
}
func TestV39SQLDepthScreensAllPointsBeforeTiming(t *testing.T) {
	base := model.Response{StatusCode: 200, Body: []byte(`{"ok":true}`), Elapsed: 10 * time.Millisecond}
	ctx := testContext(t, "GET /?id=1&uid=2 HTTP/1.1\r\nHost: bank.test\r\n\r\n", base)
	ctx.Baselines = []model.Response{base, base}
	ctx.RequestBudget = 16
	seen := map[string]bool{}
	ctx.SendFunc = func(_ context.Context, r *httpraw.Request) (model.Response, error) {
		u, _ := url.Parse(r.Target)
		for _, name := range []string{"id", "uid"} {
			if strings.Contains(u.Query().Get(name), "AND") {
				seen[name] = true
			}
		}
		if strings.Contains(strings.ToLower(r.Target), "sleep") {
			t.Fatal("deep timing preceded fair screen")
		}
		return base, nil
	}
	_, err := (SQLInjectionDeep{}).Scan(ctx)
	if !errors.Is(err, ErrPluginBudgetExhausted) || !seen["id"] || !seen["uid"] {
		t.Fatalf("unfair screen: %v %v", seen, err)
	}
}
func TestV39SQLTimingRepeatedRowScale(t *testing.T) {
	ctx := testContext(t, "GET /?id=1 HTTP/1.1\r\nHost: bank.test\r\n\r\n", model.Response{StatusCode: 200})
	pairs := pairPayloads(ctx.Rule("sqli_timing").Payloads, "time_control", "time_delay")
	pair := pairs[0]
	i := 0
	ctx.SendFunc = func(_ context.Context, r *httpraw.Request) (model.Response, error) {
		dur := []time.Duration{20 * time.Millisecond, 6020 * time.Millisecond, 6020 * time.Millisecond, 20 * time.Millisecond, 3020 * time.Millisecond, 20 * time.Millisecond}[i]
		i++
		return model.Response{StatusCode: 200, Elapsed: dur}, nil
	}
	_, confirmed, err := probeSQLTiming(ctx, (SQLInjectionTiming{}).Meta(), ctx.Points[0], pair, func(int) {})
	if err != nil || !confirmed {
		t.Fatalf("scaled doses rejected: %v", err)
	}
	pair.right.Payload = "WAITFOR DELAY '00:00:03'"
	_, confirmed, err = probeSQLTiming(ctx, (SQLInjectionTiming{}).Meta(), ctx.Points[0], pair, func(int) {})
	if err != nil || confirmed || len(ctx.CoverageIssues()) == 0 {
		t.Fatal("unsupported dose silently marked complete")
	}
}
