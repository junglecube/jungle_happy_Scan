package plugin

import (
	"context"
	"html"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

func TestV310XXEFormFieldContainingXML(t *testing.T) {
	raw := "POST /submit HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ncosp=<?xml version=\"1.0\"?><root><value>original</value></root>&b=123&c=keep"
	ctx := testContext(t, raw, model.Response{StatusCode: 200, Body: []byte("baseline")})
	ctx.Points = httpraw.DiscoverAdvanced(ctx.Request, ctx.Config)
	rule := ctx.Rule("xxe")
	rule.Payloads = rule.Payloads[:1]
	ctx.Config.PluginRules["xxe"] = rule
	applicable, reason := pluginApplicable("xxe", ctx.Request, ctx.Points, ctx.Config)
	if !applicable {
		t.Fatalf("nested form XML should be applicable, reason=%q points=%#v", reason, ctx.Points)
	}
	entity := regexp.MustCompile(`<!ENTITY\s+jungle_happy_scan\s+"([^"]+)">`)
	ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
		values, err := url.ParseQuery(string(request.Body))
		if err != nil {
			t.Fatalf("form body is no longer parseable: %v body=%q", err, request.Body)
		}
		if values.Get("b") != "123" || values.Get("c") != "keep" {
			t.Fatalf("unrelated form fields changed: %q", request.Body)
		}
		match := entity.FindStringSubmatch(values.Get("cosp"))
		if len(match) != 2 {
			t.Fatalf("nested XML did not receive a document-level entity: %q", values.Get("cosp"))
		}
		return model.Response{StatusCode: 200, Body: []byte(html.UnescapeString(match[1]))}, nil
	}
	findings, err := (XXE{}).Scan(ctx)
	if err != nil || len(findings) == 0 {
		t.Fatalf("nested form XML XXE was not detected: findings=%#v err=%v", findings, err)
	}
}

func TestV310XSSHTMLXMLBodyAndVisibility(t *testing.T) {
	cases := []struct {
		name string
		body func(string) string
		want string
	}{
		{"xml-body-json-text", func(value string) string {
			return `<XMLBODY><Field id="result">{"factoryId":"` + value + `"}</Field></XMLBODY>`
		}, "visible"},
		{"hidden-input", func(value string) string {
			return `<html><input type="hidden" value="` + value + `"></html>`
		}, "hidden-input"},
		{"display-none-ancestor", func(value string) string {
			return `<html><div style="display:none">` + value + `</div></html>`
		}, "hidden-ancestor"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := testContext(t, "GET /search?q=hello HTTP/1.1\r\nHost: bank.test\r\n\r\n", model.Response{StatusCode: 200, Headers: htmlHeader(), Body: []byte(tc.body("baseline"))})
			ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
				parsed, _ := url.Parse(request.Target)
				return model.Response{StatusCode: 200, Headers: htmlHeader(), Body: []byte(tc.body(parsed.Query().Get("q")))}, nil
			}
			findings, err := (ReflectedXSS{}).Scan(ctx)
			if err != nil || len(findings) == 0 {
				t.Fatalf("XSS in %s was missed: findings=%#v err=%v", tc.name, findings, err)
			}
			foundVisibility := false
			for _, evidence := range findings[0].Evidence {
				if got, _ := evidence.Metrics["visibility"].(string); got == tc.want {
					foundVisibility = true
				}
			}
			if !foundVisibility {
				t.Fatalf("visibility metadata missing: want=%q evidence=%#v", tc.want, findings[0].Evidence)
			}
		})
	}
}

func TestV310XSSCSPIsMitigationMetadata(t *testing.T) {
	ctx := testContext(t, "GET /search?q=hello HTTP/1.1\r\nHost: bank.test\r\n\r\n", model.Response{StatusCode: 200, Headers: htmlHeader(), Body: []byte("<html>baseline</html>")})
	ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
		parsed, _ := url.Parse(request.Target)
		return model.Response{
			StatusCode: 200,
			Headers:    map[string]string{"content-type": "text/html", "content-security-policy": "script-src 'self'"},
			Body:       []byte("<html>" + parsed.Query().Get("q") + "</html>"),
		}, nil
	}
	findings, err := (ReflectedXSS{}).Scan(ctx)
	if err != nil || len(findings) == 0 {
		t.Fatalf("CSP response reflection should remain visible: findings=%#v err=%v", findings, err)
	}
	if !strings.Contains(findings[0].Title, "CSP") {
		t.Fatalf("CSP mitigation was not reflected in title: %#v", findings[0])
	}
	blocked := false
	for _, evidence := range findings[0].Evidence {
		if value, _ := evidence.Metrics["csp_blocks_inline"].(bool); value {
			blocked = true
		}
	}
	if !blocked {
		t.Fatalf("CSP mitigation metadata missing: %#v", findings[0].Evidence)
	}
}
