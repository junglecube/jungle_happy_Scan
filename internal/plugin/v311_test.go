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

func TestV311DeepXSSFindsIMGWhenSVGIsFiltered(t *testing.T) {
	raw := "POST /factory HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nfactoryId=hello"
	ctx := testContext(t, raw, model.Response{StatusCode: 200, Headers: htmlHeader(), Body: []byte(`<XMLBODY><Field id="result">{"factoryId":"baseline"}</Field></XMLBODY>`)})
	ctx.Points = httpraw.DiscoverAdvanced(ctx.Request, ctx.Config)
	ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
		values, err := url.ParseQuery(string(request.Body))
		if err != nil {
			return model.Response{}, err
		}
		value := values.Get("factoryId")
		// Model the target behavior from the reported case: SVG/onload is
		// filtered, while IMG/onerror is reflected into the XML-wrapped HTML.
		if strings.Contains(strings.ToLower(value), "<svg") || strings.Contains(strings.ToLower(value), "onload") {
			value = ""
		}
		body := `<XMLBODY><Field id="result">{"factoryId":"` + value + `"}</Field></XMLBODY>`
		return model.Response{StatusCode: 200, Headers: htmlHeader(), Body: []byte(body)}, nil
	}

	findings, err := (ReflectedXSSDeep{}).Scan(ctx)
	if err != nil || len(findings) == 0 {
		t.Fatalf("deep XSS missed IMG reflection after SVG filtering: findings=%#v err=%v", findings, err)
	}
	if findings[0].PluginID != "reflected_xss_deep" {
		t.Fatalf("unexpected plugin ID: %#v", findings[0])
	}
	foundIMG := false
	for _, evidence := range findings[0].Evidence {
		payloadRule, _ := evidence.Metrics["payload_rule"].(string)
		if strings.Contains(strings.ToLower(payloadRule), "img") {
			foundIMG = true
		}
	}
	if !foundIMG {
		t.Fatalf("finding did not record an IMG payload rule: %#v", findings[0].Evidence)
	}
}

func TestV311DeepXSSIncludesOneLinerAndSelectionDeduplicates(t *testing.T) {
	deep := config.Default().PluginRules["reflected_xss_deep"]
	foundOneLiner := false
	for _, payload := range deep.Payloads {
		if strings.Contains(payload.Payload, "self[0X10f8809.toString") {
			foundOneLiner = true
			break
		}
	}
	if !foundOneLiner {
		t.Fatal("deep XSS defaults do not include the self-indexed one-liner payload")
	}
	selected, err := Select([]string{"reflected_xss", "reflected_xss_deep"}, "standard")
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 1 || selected[0].Meta().ID != "reflected_xss_deep" {
		t.Fatalf("quick/deep XSS selection was not deduplicated: %#v", selected)
	}
}
