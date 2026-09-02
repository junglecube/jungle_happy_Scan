package plugin

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

func TestSMSAbuseUsesConcurrentBombingAndSprayingBatches(t *testing.T) {
	ctx := testContext(t,
		"POST /sms/send HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/json\r\n\r\n{\"mobile\":\"13800138000\"}",
		model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"code":"000000","message":"发送成功"}`)},
	)
	var active atomic.Int64
	var maximum atomic.Int64
	var requests atomic.Int64
	ctx.SendFunc = func(_ context.Context, _ *httpraw.Request) (model.Response, error) {
		requests.Add(1)
		now := active.Add(1)
		for {
			old := maximum.Load()
			if now <= old || maximum.CompareAndSwap(old, now) {
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
		active.Add(-1)
		return model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"code":"000000","message":"短信发送成功"}`)}, nil
	}
	findings, err := (SMSAbuse{}).Scan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected bombing and spraying findings, got %#v", findings)
	}
	if requests.Load() != 60 {
		t.Fatalf("SMS bombing and spraying must each send 30 requests, sent=%d", requests.Load())
	}
	if maximum.Load() < 20 {
		t.Fatalf("SMS batch was not highly concurrent, maximum active=%d", maximum.Load())
	}
	for _, finding := range findings {
		if finding.PluginID != "sms_abuse" || finding.Severity != model.SeverityHigh {
			t.Fatalf("unexpected SMS finding: %#v", finding)
		}
	}
}

func TestSMSAbuseMatchesUnquotedCodeAndGenericSuccessMessage(t *testing.T) {
	ctx := testContext(t,
		"GET /sms/send?phone=13800138000 HTTP/1.1\r\nHost: bank.test\r\n\r\n",
		model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"msg":"发送成功", "code":200}`)},
	)
	rule := ctx.Config.PluginRules["sms_abuse"]
	rule.Patterns[0].Pattern = `THIS_OLD_CONFIG_PATTERN_DOES_NOT_MATCH`
	ctx.Config.PluginRules["sms_abuse"] = rule
	ctx.SendFunc = func(_ context.Context, _ *httpraw.Request) (model.Response, error) {
		return model.Response{
			StatusCode: 200,
			Headers:    jsonHeader(),
			Body:       []byte(`{"msg":"发送成功", "code":200}`),
		}, nil
	}
	findings, err := (SMSAbuse{}).Scan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected bombing and spraying findings for code:200 response, got %#v", findings)
	}
}

func TestSMSAbuseRequiresConfiguredURLKeyword(t *testing.T) {
	ctx := testContext(t,
		"POST /account/update HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/json\r\n\r\n{\"phone\":\"13800138000\"}",
		model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"code":200}`)},
	)
	var requests atomic.Int64
	ctx.SendFunc = func(_ context.Context, _ *httpraw.Request) (model.Response, error) {
		requests.Add(1)
		return model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"code":200}`)}, nil
	}
	findings, err := (SMSAbuse{}).Scan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 || requests.Load() != 0 {
		t.Fatalf("non-SMS URL must not run SMS batches: findings=%d requests=%d", len(findings), requests.Load())
	}
}

func TestSMSAbuseAcceptsPersistedAdditionalURLKeyword(t *testing.T) {
	ctx := testContext(t,
		"POST /otp/message HTTP/1.1\r\nHost: bank.test\r\nContent-Type: application/json\r\n\r\n{\"phone\":\"13800138000\"}",
		model.Response{StatusCode: 200, Headers: jsonHeader(), Body: []byte(`{"code":200}`)},
	)
	rule := ctx.Config.PluginRules["sms_abuse"]
	rule.URLKeywords = append(rule.URLKeywords, "message")
	ctx.Config.PluginRules["sms_abuse"] = rule
	var requests atomic.Int64
	ctx.SendFunc = func(_ context.Context, _ *httpraw.Request) (model.Response, error) {
		requests.Add(1)
		return model.Response{StatusCode: 429, Headers: jsonHeader(), Body: []byte(`{"code":429}`)}, nil
	}
	if _, err := (SMSAbuse{}).Scan(ctx); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 60 {
		t.Fatalf("additional SMS URL keyword should enable both batches, sent=%d", requests.Load())
	}
}
