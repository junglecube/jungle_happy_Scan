package plugin

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

func TestSQLV24CleanQuoteGateStillRunsNumericBooleanOracle(t *testing.T) {
	baseline := model.Response{
		StatusCode: 200, Headers: jsonHeader(),
		Body: []byte(`{"code":0,"rows":[1,2,3],"message":"success"}`),
	}
	ctx := testContext(t, "GET /query?id=1 HTTP/1.1\r\nHost: bank.test\r\n\r\n", baseline)
	ctx.Baselines = []model.Response{baseline, baseline}
	sends := 0
	ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
		sends++
		parsed, _ := url.Parse(request.Target)
		value := parsed.Query().Get("id")
		if strings.Contains(value, "731=732") {
			return model.Response{
				StatusCode: 200, Headers: jsonHeader(),
				Body: []byte(`{"code":0,"rows":[],"message":"success"}`),
			}, nil
		}
		// The quote gate is deliberately clean. V2.3 stopped here and missed the
		// numeric Boolean oracle; V2.4 must continue with the numeric context.
		return baseline, nil
	}

	findings, err := (SQLInjection{}).Scan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Title != "SQL 布尔盲注" {
		t.Fatalf("clean quote gate suppressed numeric Boolean confirmation: sends=%d findings=%+v", sends, findings)
	}
	if sends != 5 {
		t.Fatalf("expected one quote gate plus A-B-B-A numeric probes, got %d", sends)
	}
}

func TestSQLV24RecursiveBusinessOutcome(t *testing.T) {
	tests := []struct {
		body string
		want string
	}{
		{`{"head":{"returnCode":"-3","message":"系统异常"}}`, "returncode:-3"},
		{`{"result":{"error_code":731}}`, "errorcode:731"},
		{`[{"payload":{"success":false}}]`, "success:false"},
	}
	for _, test := range tests {
		got, ok := sqlBusinessOutcome(model.Response{Body: []byte(test.body)})
		if !ok || got != test.want {
			t.Fatalf("recursive outcome for %s = %q, %v; want %q", test.body, got, ok, test.want)
		}
	}
}

func TestSQLV24BusinessOutcomeUsesTheSameJSONPath(t *testing.T) {
	response := func(body string) model.Response {
		return model.Response{StatusCode: 200, Body: []byte(body), Headers: jsonHeader()}
	}
	baseline := response(`{"status":"ok","data":[{"code":"ROW-A"}]}`)
	controlOne := response(`{"status":"ok","data":[{"code":"ROW-B"}]}`)
	controlTwo := response(`{"status":"ok","data":[{"code":"ROW-C"}]}`)
	errorOne := response(`{"status":"error","data":[{"code":"ROW-D"}]}`)
	errorTwo := response(`{"status":"error","data":[{"code":"ROW-E"}]}`)
	if !sqlBusinessOutcomeABBA(baseline, controlOne, errorOne, errorTwo, controlTwo) {
		t.Fatal("stable envelope status should remain an oracle when nested row codes vary")
	}
}

func TestSQLV24ConfiguredOutcomeSupportsLegacyJSP(t *testing.T) {
	cfg := config.Default()
	cfg.SuccessPatterns = []string{`处理成功`}
	cfg.DeniedPatterns = []string{`系统处理异常`}
	response := func(body string) model.Response {
		return model.Response{StatusCode: 200, Body: []byte("<html><script>" + body + "</script></html>")}
	}
	baseline := response(`window.message="处理成功";window.rows=[1,2,3]`)
	controlOne := response(`window.message="处理成功";window.rows=[1,2,3]`)
	controlTwo := response(`window.message="处理成功";window.rows=[1,2,3]`)
	errorOne := response(`window.message="系统处理异常";window.rows=[]`)
	errorTwo := response(`window.message="系统处理异常";window.rows=[]`)
	if !sqlBusinessOutcomeABBAConfigured(cfg, baseline, controlOne, errorOne, errorTwo, controlTwo) {
		t.Fatal("configured success/error semantics should support legacy JSP outcomes")
	}
}

func TestSQLV24UnknownDialectUsesBoundedPortableFallback(t *testing.T) {
	pairs := []payloadPair{
		{group: "mysql-exp-string"},
		{group: "postgres-exp-string"},
		{group: "portable-exp-string"},
		{group: "postgres-another"},
	}
	selected := selectSQLConditionalPairs(pairs, sqlPatternMatch{name: "Spring 统一业务错误"})
	if len(selected) != 3 ||
		selected[0].group != "portable-exp-string" ||
		selected[1].group != "postgres-exp-string" ||
		selected[2].group != "mysql-exp-string" {
		t.Fatalf("unexpected unknown-dialect fallback: %+v", selected)
	}
	mysql := selectSQLConditionalPairs(pairs, sqlPatternMatch{name: "MySQL/JDBC 异常"})
	if len(mysql) != 1 || mysql[0].group != "mysql-exp-string" {
		t.Fatalf("explicit MySQL fingerprint was not respected: %+v", mysql)
	}
}

func TestSQLV24DuplicateGroupsPairInConfigurationOrder(t *testing.T) {
	rules := []config.PayloadRule{
		{Name: "L1", Kind: "boolean_true", Group: "same", Payload: "left-1"},
		{Name: "L2", Kind: "boolean_true", Group: "same", Payload: "left-2"},
		{Name: "R1", Kind: "boolean_false", Group: "same", Payload: "right-1"},
		{Name: "R2", Kind: "boolean_false", Group: "same", Payload: "right-2"},
	}
	pairs := pairPayloads(rules, "boolean_true", "boolean_false")
	if len(pairs) != 2 ||
		pairs[0].left.Name != "L1" || pairs[0].right.Name != "R1" ||
		pairs[1].left.Name != "L2" || pairs[1].right.Name != "R2" {
		t.Fatalf("duplicate group members were overwritten or reordered: %+v", pairs)
	}
}

func TestSQLV24BaselinePatternDoesNotDirtyRecovery(t *testing.T) {
	patterns := compileDetectionPatterns([]config.DetectionRule{
		{Name: "页面原有提示", Pattern: `error`, Severity: "low", Confidence: "firm"},
		{Name: "MySQL/JDBC 异常", Pattern: `MySQLSyntaxErrorException`, Severity: "high", Confidence: "certain"},
	})
	baseline := map[string]bool{"页面原有提示": true}
	if hasNovelSQLPattern(patterns, []byte(`{"error":null}`), baseline) {
		t.Fatal("baseline-existing pattern was incorrectly treated as a dirty recovery")
	}
	match := bestNovelPatternRule(patterns, []byte(`error MySQLSyntaxErrorException`), baseline)
	if match.name != "MySQL/JDBC 异常" {
		t.Fatalf("novel high-value database evidence was hidden by baseline text: %+v", match)
	}
}

func TestSQLV24LongResponseCannotUseSampledExactRecovery(t *testing.T) {
	leftBody := []byte(strings.Repeat("A", 700_000))
	rightBody := append([]byte(nil), leftBody...)
	// This position is outside the diff package's head/middle/tail sample.
	rightBody[300_000] = 'B'
	left := model.Response{StatusCode: 200, Body: leftBody}
	right := model.Response{StatusCode: 200, Body: rightBody}
	if sqlEquivalentResponse(left, right, config.Default()) {
		t.Fatal("different long responses were incorrectly classified as exact recovery")
	}
}

func TestSQLV24PairConfirmationIsAtomicallyBudgeted(t *testing.T) {
	baseline := model.Response{
		StatusCode: 200, Headers: jsonHeader(),
		Body: []byte(`{"code":0,"data":[731]}`),
	}
	ctx := testContext(t, "GET /query?id=731 HTTP/1.1\r\nHost: bank.test\r\n\r\n", baseline)
	ctx.Baselines = []model.Response{baseline, baseline}
	ctx.RequestBudget = 4 // enough for the gate, but not the complete A-B-B-A cohort
	sends := 0
	budgetSkipped := 0
	ctx.OnResolution = func(kind string, count int) {
		if kind == "budget_skipped" {
			budgetSkipped += count
		}
	}
	ctx.SendFunc = func(_ context.Context, _ *httpraw.Request) (model.Response, error) {
		sends++
		return model.Response{
			StatusCode: 500, Headers: jsonHeader(),
			Body: []byte(`org.postgresql.util.PSQLException: unterminated quoted string`),
		}, nil
	}

	findings, err := (SQLInjection{}).Scan(ctx)
	if err != nil && !errors.Is(err, ErrPluginBudgetExhausted) {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("partial observation produced a finding: %+v", findings)
	}
	if sends != 1 {
		t.Fatalf("confirmation cohort was partially sent: sends=%d", sends)
	}
	if budgetSkipped < 4 {
		t.Fatalf("atomic reservation failure was not classified as budget_skipped: %d", budgetSkipped)
	}
}

func TestSQLV24PairedEvidenceCarriesMachineReadableOrder(t *testing.T) {
	baseline := model.Response{
		StatusCode: 200, Headers: jsonHeader(),
		Body: []byte(`{"code":0,"rows":[1,2,3]}`),
	}
	ctx := testContext(t, "GET /query?id=1 HTTP/1.1\r\nHost: bank.test\r\n\r\n", baseline)
	ctx.Baselines = []model.Response{baseline, baseline}
	ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
		parsed, _ := url.Parse(request.Target)
		if strings.Contains(parsed.Query().Get("id"), "731=732") {
			return model.Response{
				StatusCode: 200, Headers: jsonHeader(),
				Body: []byte(`{"code":0,"rows":[]}`),
			}, nil
		}
		return baseline, nil
	}

	findings, err := (SQLInjection{}).Scan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || len(findings[0].Evidence) != 4 {
		t.Fatalf("expected one four-part Boolean finding: %+v", findings)
	}
	wantRoles := []string{"true", "false", "false", "true"}
	for index, evidence := range findings[0].Evidence {
		if evidence.Strength != "L4" ||
			evidence.Metrics["pair_order"] != "A-B-B-A" ||
			evidence.Metrics["pair_sequence"] != index+1 ||
			evidence.Metrics["pair_role"] != wantRoles[index] {
			t.Fatalf("evidence %d lacks paired metadata: %+v", index, evidence)
		}
	}
}

func TestSQLV24CompactPatternConfidenceIsNotPromoted(t *testing.T) {
	patterns := compileSQLDetectionPatternsWithConfidence(nil, []string{`(?i)database error`}, "firm")
	match := bestPatternRule(patterns, []byte("database error"))
	_, confidence := match.severityConfidence()
	if confidence != model.ConfidenceFirm {
		t.Fatalf("free-form SQL pattern confidence was promoted: %+v", match)
	}
}

func TestSQLV24StableLongShellUsesExactBooleanOracle(t *testing.T) {
	baselineBody := []byte("<html><body>" + strings.Repeat("stable-shell-731 ", 44_000) + "</body></html>")
	falseBody := append([]byte(nil), baselineBody...)
	// Keep the change outside the generic differential's head/middle/tail
	// sample. The SQL oracle must still recognize the repeated raw-body delta.
	falseBody[275_000] = 'X'
	baseline := model.Response{
		StatusCode: 200,
		Headers:    map[string]string{"content-type": "text/html; charset=UTF-8"},
		Body:       baselineBody,
	}
	ctx := testContext(t, "GET /query?id=1 HTTP/1.1\r\nHost: bank.test\r\n\r\n", baseline)
	ctx.Baselines = []model.Response{baseline, baseline}
	sends := 0
	ctx.SendFunc = func(_ context.Context, request *httpraw.Request) (model.Response, error) {
		sends++
		parsed, _ := url.Parse(request.Target)
		if strings.Contains(parsed.Query().Get("id"), "731=732") {
			return model.Response{StatusCode: 200, Headers: baseline.Headers, Body: falseBody}, nil
		}
		return baseline, nil
	}

	findings, err := (SQLInjection{}).Scan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Title != "SQL 布尔盲注" || sends != 5 {
		t.Fatalf("stable long-shell exact oracle was missed: sends=%d findings=%+v", sends, findings)
	}
	if findings[0].Evidence[0].Metrics["exact_oracle"] != true {
		t.Fatalf("finding did not disclose the exact-response branch: %+v", findings[0].Evidence[0].Metrics)
	}
}
