package diff

import (
	"fmt"
	"strings"
	"testing"

	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/model"
)

func TestRuntimeCachesStayBounded(t *testing.T) {
	cfg := config.Default()
	for index := 0; index < maxCachedRegexps+20; index++ {
		cfg.DynamicPatterns = []string{fmt.Sprintf("dynamic-%d", index)}
		_ = Normalize(model.Response{StatusCode: 200, Body: []byte("stable body")}, cfg)
	}
	compiledRegexps.mu.Lock()
	regexpCount := len(compiledRegexps.items)
	compiledRegexps.mu.Unlock()
	normalizedResponses.mu.Lock()
	normalizedCount := len(normalizedResponses.items)
	normalizedResponses.mu.Unlock()
	if regexpCount > maxCachedRegexps || normalizedCount > maxNormalizedResponses {
		t.Fatalf("runtime caches grew past bounds: regexps=%d normalized=%d", regexpCount, normalizedCount)
	}
}

func TestSimilarityNormalizesDynamicJSON(t *testing.T) {
	cfg := config.Default()
	left := model.Response{StatusCode: 200, Headers: map[string]string{"content-type": "application/json"}, Body: []byte(`{"code":"000000","requestId":"aaaaaaaaaaaaaaaa","data":{"name":"A"}}`)}
	right := model.Response{StatusCode: 200, Headers: map[string]string{"content-type": "application/json"}, Body: []byte(`{"requestId":"bbbbbbbbbbbbbbbb","data":{"name":"A"},"code":"000000"}`)}
	if score := Similarity(left, right, cfg); score < 0.99 {
		t.Fatalf("expected normalized responses to match, score=%f", score)
	}
}

func TestNormalizeHTMLAndLongResponseSegments(t *testing.T) {
	cfg := config.Default()
	cfg.DynamicPatterns = append(cfg.DynamicPatterns, `var nonce=\d+`)
	left := model.Response{StatusCode: 200, Headers: map[string]string{"content-type": "text/html"}, Body: []byte(`<!doctype html><html><!--one--><script>var nonce=1</script><style>.x{}</style><input type="hidden" value="a"><body>A&amp;B</body></html>`)}
	right := model.Response{StatusCode: 200, Headers: map[string]string{"content-type": "text/html"}, Body: []byte(`<!doctype html><html><!--two--><script>var nonce=2</script><style>.y{}</style><input type="hidden" value="b"><body>A&amp;B</body></html>`)}
	if score := Similarity(left, right, cfg); score < 0.99 {
		t.Fatalf("HTML noise was not normalized: %f\nleft=%q\nright=%q", score, Normalize(left, cfg), Normalize(right, cfg))
	}

	body := []byte(strings.Repeat("H", 300_000) + strings.Repeat("M", 300_000) + strings.Repeat("T", 300_000))
	sampled := sampleSegments(body, 500_000)
	if len(sampled) < 500_000 || !strings.Contains(sampled, "<jhs-segment>") || !strings.Contains(sampled, "M") || !strings.HasSuffix(sampled, strings.Repeat("T", 100)) {
		t.Fatalf("long response did not retain bounded head/middle/tail: len=%d", len(sampled))
	}
}

func TestNormalizePreservesLegacyJSPInlineBusinessData(t *testing.T) {
	cfg := config.Default()
	left := model.Response{StatusCode: 200, Headers: map[string]string{"content-type": "text/html"}, Body: []byte(`<html><script>window.result={"code":0,"rows":[1,2,3]}</script></html>`)}
	right := model.Response{StatusCode: 200, Headers: map[string]string{"content-type": "text/html"}, Body: []byte(`<html><script>window.result={"code":-3,"rows":[]}</script></html>`)}
	if Normalize(left, cfg) == Normalize(right, cfg) {
		t.Fatal("inline JSP/JavaScript business outcome was discarded during normalization")
	}
}

func TestSimilarityStatusEmptyAndBaselineStability(t *testing.T) {
	cfg := config.Default()
	if score := Similarity(model.Response{StatusCode: 200, Body: []byte("same")}, model.Response{StatusCode: 500, Body: []byte("same")}, cfg); score != 0 {
		t.Fatalf("different status families matched: %f", score)
	}
	if score := Similarity(model.Response{StatusCode: 200}, model.Response{StatusCode: 200, Body: []byte("data")}, cfg); score != 0 {
		t.Fatalf("empty and nonempty responses matched: %f", score)
	}
	responses := []model.Response{{StatusCode: 200, Body: []byte("alpha beta gamma delta")}, {StatusCode: 200, Body: []byte("alpha beta gamma delta")}, {StatusCode: 200, Body: []byte("alpha beta gamma changed")}}
	if stability := BaselineStability(responses, cfg); stability <= 0 || stability >= 1 {
		t.Fatalf("unexpected multi-sample stability: %f", stability)
	}
	if BaselineStability(responses[:1], cfg) != 1 {
		t.Fatal("single baseline must be stable by definition")
	}
}

func TestRepresentativeBaselineChoosesStableMedoid(t *testing.T) {
	cfg := config.Default()
	responses := []model.Response{
		{StatusCode: 200, Body: []byte(`{"code":200,"rows":[{"id":1}]}`)},
		{StatusCode: 200, Body: []byte(`{"code":200,"rows":[{"id":1}]}`)},
		{StatusCode: 503, Body: []byte(`gateway temporarily unavailable`)},
	}
	if index := RepresentativeBaselineIndex(responses, cfg); index != 1 {
		t.Fatalf("representative baseline index=%d, want newest stable medoid 1", index)
	}
	if index := RepresentativeBaselineIndex(nil, cfg); index != 0 {
		t.Fatalf("empty baseline index=%d, want safe zero", index)
	}
}

func TestSimilarityPreservesRepeatedBusinessRowCounts(t *testing.T) {
	cfg := config.Default()
	left := model.Response{StatusCode: 200, Body: []byte(strings.Repeat("business row approved ", 20))}
	right := model.Response{StatusCode: 200, Body: []byte("business row approved ")}
	if score := Similarity(left, right, cfg); score >= 0.90 {
		t.Fatalf("multiset fingerprint discarded repeated row counts: %f", score)
	}
	prefix := []byte(strings.Repeat("retained ", 100))
	short := model.Response{StatusCode: 200, Body: prefix, RawBytes: 1_000, Truncated: true}
	long := model.Response{StatusCode: 200, Body: prefix, RawBytes: 2_000, Truncated: true}
	if score := Similarity(short, long, cfg); score >= 0.94 {
		t.Fatalf("fingerprint discarded original truncated response length: %f", score)
	}
}

func TestSuccessDeniedExcerptAndShingleEdges(t *testing.T) {
	cfg := config.Default()
	if !LikelyAuthDenied(model.Response{StatusCode: 401}, cfg) || !LikelyAuthDenied(model.Response{StatusCode: 403}, cfg) {
		t.Fatal("HTTP authentication denial status was not recognized")
	}
	if LikelySuccess(model.Response{StatusCode: 500, Body: []byte(`{"code":200}`)}, cfg) {
		t.Fatal("non-2xx response was treated as success")
	}
	if !LikelySuccess(model.Response{StatusCode: 200, Body: []byte(`{"code":200}`)}, cfg) {
		t.Fatal("configured success response was not recognized")
	}
	if !LikelySuccess(model.Response{StatusCode: 204}, cfg) {
		t.Fatal("clean 2xx fallback was not recognized")
	}
	if LikelySuccess(model.Response{StatusCode: 200, Body: []byte("请登录")}, cfg) {
		t.Fatal("business denial was treated as success")
	}
	excerpt := Excerpt(strings.Repeat("x", 200)+"TARGET"+strings.Repeat("y", 200), "target", 90)
	if len(excerpt) != 90 || !strings.Contains(excerpt, "TARGET") {
		t.Fatalf("marker-centered excerpt failed: len=%d value=%q", len(excerpt), excerpt)
	}
	if len(Excerpt("short text", "", 0)) != len("short text") || len(shingles("")) != 1 || len(shingles("one two")) != 1 || len(shingles("one two three four")) != 2 {
		t.Fatal("excerpt/shingle edge cases failed")
	}
}

func TestAuthDeniedBusinessResponse(t *testing.T) {
	cfg := config.Default()
	response := model.Response{StatusCode: 200, Headers: map[string]string{}, Body: []byte(`{"code":"401","message":"请登录"}`)}
	if !LikelyAuthDenied(response, cfg) {
		t.Fatal("business auth failure was not detected")
	}
}

func TestAuthDeniedPatternMatchesStatusReasonAndFlexibleWhitespace(t *testing.T) {
	cfg := config.Default()
	cfg.DeniedPatterns = []string{`503 Service Unavailable`}

	// The raw response view includes the HTTP status line, while Response keeps
	// only its numeric status code. The configured phrase must still match.
	if !LikelyAuthDenied(model.Response{StatusCode: 503, Body: []byte("upstream unavailable")}, cfg) {
		t.Fatal("status reason was not available to configured denial patterns")
	}

	// Gateways may wrap the phrase or use a non-breaking space in HTML text.
	if !LikelyAuthDenied(model.Response{StatusCode: 200, Body: []byte("<h1>503\nService\u00a0\u00a0Unavailable</h1>")}, cfg) {
		t.Fatal("configured denial pattern did not tolerate response whitespace")
	}
}
