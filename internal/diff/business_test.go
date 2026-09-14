package diff

import (
	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/model"
	"testing"
)

func strptr(s string) *string { return &s }
func TestBusinessV39FailureWinsAndUnknownIsNotSuccess(t *testing.T) {
	cfg := config.Default()
	for _, tt := range []struct {
		body string
		want Outcome
	}{
		{`{"code":200,"success":false,"msg":"发送失败，请稍后重试"}`, Failure},
		{`{"code":0,"message":"请求频繁"}`, Failure},
		{`{"code":0}`, Success}, {`{"ok":"unspecified"}`, Unknown},
		{`{"data":{"code":0}}`, Unknown},
	} {
		got := EvaluateBusiness(model.Response{StatusCode: 200, Body: []byte(tt.body)}, cfg, "sms_abuse", "/send")
		if got.Outcome != tt.want {
			t.Fatalf("%s => %s, want %s", tt.body, got.Outcome, tt.want)
		}
	}
}
func TestBusinessV39ScopedJSONRules(t *testing.T) {
	cfg := config.Default()
	cfg.BusinessRules = []config.BusinessRule{
		{Name: "custom ok", PluginIDs: []string{"sms_abuse"}, URLPattern: `^/otp/`, JSONPath: "$.data.items[0].code", Equals: strptr("OK"), Outcome: "success"},
		{Name: "custom fail", PluginIDs: []string{"sms_abuse"}, JSONPath: "$.data.accepted", Equals: strptr("false"), Outcome: "failure"},
	}
	r := model.Response{StatusCode: 200, Body: []byte(`{"data":{"items":[{"code":"OK"}]}}`)}
	for _, tt := range []struct {
		id, url string
		want    Outcome
	}{{"sms_abuse", "/otp/send", Success}, {"file_upload", "/otp/send", Unknown}, {"sms_abuse", "/other", Unknown}} {
		if got := EvaluateBusiness(r, cfg, tt.id, tt.url); got.Outcome != tt.want {
			t.Fatalf("%+v => %+v", tt, got)
		}
	}
	r.Body = []byte(`{"data":{"items":[{"code":"OK"}],"accepted":false}}`)
	if got := EvaluateBusiness(r, cfg, "sms_abuse", "/otp/send"); got.Outcome != Failure || got.Rule != "custom fail" {
		t.Fatalf("%+v", got)
	}
}
func TestBusinessV39CustomSuccessCode(t *testing.T) {
	cfg := config.Default()
	cfg.BusinessRules = []config.BusinessRule{{Name: "business 1000", JSONPath: "$.code", Equals: strptr("1000"), Outcome: "success"}}
	for _, tt := range []struct {
		body string
		want Outcome
	}{{`{"code":1000}`, Success}, {`{"code":1000,"success":false}`, Failure}} {
		if got := EvaluateBusiness(model.Response{StatusCode: 200, Body: []byte(tt.body)}, cfg, "file_upload", "/"); got.Outcome != tt.want {
			t.Fatalf("%s: %+v", tt.body, got)
		}
	}
}
