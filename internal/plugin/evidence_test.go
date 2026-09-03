package plugin

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

func TestEvidenceKeepsHeadersAndMarkerLineContext(t *testing.T) {
	originalLines := make([]string, 100)
	mutatedLines := make([]string, 100)
	for i := range originalLines {
		originalLines[i] = "field-" + string(rune('a'+i%26))
		mutatedLines[i] = originalLines[i]
	}
	originalLines[0] = strings.Repeat("outside-window-", 5000)
	mutatedLines[0] = originalLines[0]
	mutatedLines[50] = "field-50 TARGET"
	ctx := testContext(t, "POST /submit HTTP/1.1\r\nHost: bank.test\r\nX-Trace: keep-me\r\n\r\n"+strings.Join(originalLines, "\n"), model.Response{})
	mutated, err := httpraw.Parse("POST /submit HTTP/1.1\r\nHost: bank.test\r\nX-Trace: keep-me\r\n\r\n"+strings.Join(mutatedLines, "\n"), "https")
	if err != nil {
		t.Fatal(err)
	}
	response := model.Response{
		StatusCode: 200,
		Headers:    map[string]string{"content-type": "text/plain", "x-evidence": "keep"},
		Body:       []byte(strings.Join(originalLines[:50], "\n") + "\nline-50 TARGET\n" + strings.Join(originalLines[51:], "\n")),
	}
	evidence := ctx.Evidence("marker context", mutated, &response, map[string]any{"match": "TARGET"})
	if !strings.Contains(evidence.Response, "x-evidence: keep") || !strings.Contains(evidence.Response, "line-50 TARGET") {
		t.Fatalf("response evidence lost headers or marker: %q", evidence.Response)
	}
	if !strings.Contains(evidence.Response, "\r\n\r\nfield-u\nfield-v") || !evidence.ResponseContextClipped || evidence.ResponseContextStrategy != "marker_lines" {
		t.Fatalf("unexpected response context: %#v", evidence)
	}
	if !evidence.RequestContextClipped || evidence.RequestContextStrategy != "marker_lines" || !strings.Contains(evidence.Request, "field-50 TARGET") {
		t.Fatalf("request evidence did not center changed field: %#v", evidence)
	}
	requestBytes, err := base64.StdEncoding.DecodeString(evidence.RequestBase64)
	if err != nil || !bytes.Equal(requestBytes, mutated.RawExact()) {
		t.Fatalf("base64 request evidence did not preserve the complete raw request: err=%v", err)
	}
	if !evidence.ResponseTruncated || evidence.ResponseCaptureTruncated {
		t.Fatalf("legacy truncation metadata is wrong: %#v", evidence)
	}
}

func TestEvidenceCentersOnResponseDiffWithoutExplicitMarker(t *testing.T) {
	lines := make([]string, 100)
	for i := range lines {
		lines[i] = "line-" + string(rune('a'+i%26))
	}
	lines[0] = strings.Repeat("outside-window-", 5000)
	baseline := model.Response{StatusCode: 200, Headers: map[string]string{"content-type": "text/plain"}, Body: []byte(strings.Join(lines, "\n"))}
	lines[50] = "line-50 KEY_EVIDENCE"
	response := baseline
	response.Body = []byte(strings.Join(lines, "\n"))
	ctx := testContext(t, "GET /submit HTTP/1.1\r\nHost: bank.test\r\n\r\n", baseline)
	evidence := ctx.Evidence("changed response", ctx.Request, &response, map[string]any{"context": "body"})
	if evidence.ResponseContextStrategy != "marker_lines" || evidence.ResponseContextStartLine != 21 || evidence.ResponseContextEndLine != 81 {
		t.Fatalf("response diff did not select a centered window: %#v", evidence)
	}
	if !strings.Contains(evidence.Response, "line-50 KEY_EVIDENCE") || !strings.HasPrefix(evidence.Response, "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n\r\nline-u\nline-v") {
		t.Fatalf("response evidence was not centered on the changed content: %q", evidence.Response)
	}
	if !strings.Contains(evidence.ResponseExcerpt, "KEY_EVIDENCE") {
		t.Fatalf("response excerpt did not reuse the response diff marker: %q", evidence.ResponseExcerpt)
	}
}

func TestEvidenceBinaryResponseUsesDescriptor(t *testing.T) {
	ctx := testContext(t, "GET /download HTTP/1.1\r\nHost: bank.test\r\n\r\n", model.Response{})
	response := model.Response{
		StatusCode: 200,
		Headers:    map[string]string{"content-type": "application/octet-stream"},
		Body:       []byte{0, 1, 2, 3},
		RawBytes:   4,
	}
	evidence := ctx.Evidence("binary", ctx.Request, &response, nil)
	if !strings.Contains(evidence.Response, "binary body") || !strings.Contains(evidence.Response, "sha256=") || strings.Contains(evidence.Response, "\x00") {
		t.Fatalf("binary response was not represented safely: %q", evidence.Response)
	}
	if evidence.ResponseContextStrategy != "binary" || evidence.ResponseBodySHA256 == "" {
		t.Fatalf("binary response metadata is incomplete: %#v", evidence)
	}
}

func TestEvidenceNeverRedactsSelectedHeadersOrBodies(t *testing.T) {
	ctx := testContext(t, "POST /submit HTTP/1.1\r\nHost: bank.test\r\nAuthorization: Bearer request-secret\r\nCookie: JSESSIONID=session-secret\r\nContent-Type: application/json\r\n\r\n{\"token\":\"request-secret\"}", model.Response{})
	ctx.Config.RedactEvidence = true
	response := model.Response{
		StatusCode: 200,
		Headers: map[string]string{
			"content-type":  "application/json",
			"set-cookie":    "JSESSIONID=response-secret; Secure",
			"authorization": "Bearer response-secret",
		},
		Body: []byte(`{"token":"body-secret","phone":"13800138000"}`),
	}
	evidence := ctx.Evidence("sensitive match", ctx.Request, &response, map[string]any{"match": "body-secret"})
	for name, value := range map[string]string{
		"request":  evidence.Request,
		"response": evidence.Response,
		"excerpt":  evidence.ResponseExcerpt,
	} {
		if strings.Contains(value, "<redacted>") {
			t.Fatalf("%s evidence was redacted despite the compatibility flag: %q", name, value)
		}
	}
	for _, expected := range []string{"request-secret", "session-secret", "JSESSIONID=response-secret", "Bearer response-secret", "body-secret", "13800138000"} {
		if !strings.Contains(evidence.Request+evidence.Response+evidence.ResponseExcerpt, expected) {
			t.Fatalf("evidence lost original value %q: %#v", expected, evidence)
		}
	}
	if ctx.Config.RedactEvidence != true || config.Default().RedactEvidence != false {
		t.Fatalf("redaction compatibility/default contract changed unexpectedly")
	}
}
