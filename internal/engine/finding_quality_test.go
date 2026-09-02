package engine

import (
	"testing"

	"jungle_happy_Scan/internal/model"
)

func TestFindingQualityDeduplicationAndCorrelation(t *testing.T) {
	items := []model.Finding{
		{ID: "a", PluginID: "sqli", Title: "SQL 错误型注入", Affected: "query:id", Severity: model.SeverityHigh, Confidence: model.ConfidenceCertain, Evidence: []model.Evidence{{}, {}, {}}},
		{ID: "duplicate", PluginID: "sqli", Title: "SQL 错误型注入", Affected: "query:id", Severity: model.SeverityHigh, Confidence: model.ConfidenceCertain},
		{ID: "b", PluginID: "error_disclosure", Title: "异常泄露", Affected: "query:id", Severity: model.SeverityMedium, Confidence: model.ConfidenceFirm, Evidence: []model.Evidence{{}, {}}},
	}
	findings, correlations := deduplicateAndCorrelate(items)
	if len(findings) != 2 || len(correlations) != 1 {
		t.Fatalf("unexpected quality result: findings=%d correlations=%d", len(findings), len(correlations))
	}
	if findings[0].Score < 85 || findings[0].Category != "确认漏洞" || findings[0].Correlation == "" {
		t.Fatalf("high-confidence paired finding was not enriched: %#v", findings[0])
	}
	if correlations[0].Affected != "query:id" || len(correlations[0].Findings) != 2 {
		t.Fatalf("unexpected correlation: %#v", correlations[0])
	}
}

func TestL5EvidenceProducesConfirmedCategory(t *testing.T) {
	finding := enrichFinding(model.Finding{
		PluginID: "ssrf", Severity: model.SeverityCritical, Confidence: model.ConfidenceCertain,
		Evidence: []model.Evidence{{Strength: "L5"}},
	})
	if finding.Category != "确认漏洞" || finding.Score < 85 {
		t.Fatalf("L5 execution/callback evidence was under-scored: %+v", finding)
	}
}

func TestInformationalFindingScoreIsCapped(t *testing.T) {
	finding := enrichFinding(model.Finding{
		ID: "safe-mode", PluginID: "json_polymorphic", Title: "JSON 多态安全策略已阻断测试类型",
		Severity: model.SeverityInfo, Confidence: model.ConfidenceCertain,
		Evidence: []model.Evidence{{}, {}, {}},
	})
	if finding.Category != "信息提示" || finding.Score > 40 {
		t.Fatalf("blocked protection signal must not look like a confirmed vulnerability: %#v", finding)
	}
}
