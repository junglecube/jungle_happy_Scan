package engine

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"jungle_happy_Scan/internal/model"
)

func enrichFinding(finding model.Finding) model.Finding {
	score := 25
	switch finding.Confidence {
	case model.ConfidenceCertain:
		score += 40
	case model.ConfidenceFirm:
		score += 25
	case model.ConfidenceTentative:
		score += 10
	}
	if len(finding.Evidence) >= 2 {
		score += 15
	}
	if len(finding.Evidence) >= 3 {
		score += 5
	}
	strongestEvidence := 0
	for _, evidence := range finding.Evidence {
		if len(evidence.Strength) == 2 && evidence.Strength[0] == 'L' && evidence.Strength[1] >= '1' && evidence.Strength[1] <= '5' {
			strongestEvidence = max(strongestEvidence, int(evidence.Strength[1]-'0'))
		}
	}
	switch strongestEvidence {
	case 5:
		score += 25
	case 4:
		score += 15
	case 3:
		score += 8
	case 2:
		score += 3
	}
	switch finding.PluginID {
	case "command_injection", "command_injection_oast", "command_injection_timing", "crlf_injection", "ssti", "file_read", "file_read_encoded":
		score += 10
	case "sqli", "sqli_extended", "sqli_timing", "sqli_order_by", "sqli_limit", "mybatis_dynamic_sql", "nosql_injection", "ldap_injection", "xpath_injection":
		score += 5
	}
	score = min(score, 100)
	category := "疑似漏洞"
	if finding.Severity == model.SeverityInfo {
		score = min(score, 40)
		category = "信息提示"
	} else {
		switch finding.PluginID {
		case "java_deserialization", "json_polymorphic", "api_exposure", "spring_actuator", "graphql_security", "graphql_alias_abuse", "security_headers":
			category = "配置暴露"
		default:
			if score >= 85 {
				category = "确认漏洞"
			} else if score < 55 {
				category = "信息提示"
			}
		}
	}
	finding.Score = score
	finding.Category = category
	return finding
}

func deduplicateAndCorrelate(items []model.Finding) ([]model.Finding, []model.FindingCorrelation) {
	seen := make(map[string]bool)
	deduped := make([]model.Finding, 0, len(items))
	for _, item := range items {
		key := item.PluginID + "\x00" + item.Affected + "\x00" + item.Title
		if seen[key] {
			continue
		}
		seen[key] = true
		deduped = append(deduped, enrichFinding(item))
	}
	groups := make(map[string][]int)
	for index, item := range deduped {
		affected := strings.TrimSpace(strings.ToLower(item.Affected))
		if affected != "" {
			groups[affected] = append(groups[affected], index)
		}
	}
	keys := make([]string, 0, len(groups))
	for key, indexes := range groups {
		if len(indexes) >= 2 {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	correlations := make([]model.FindingCorrelation, 0, len(keys))
	for _, key := range keys {
		sum := sha256.Sum256([]byte(key))
		id := fmt.Sprintf("corr_%x", sum[:6])
		indexes := groups[key]
		findingIDs := make([]string, 0, len(indexes))
		families := make(map[string]bool)
		for _, index := range indexes {
			deduped[index].Correlation = id
			findingIDs = append(findingIDs, deduped[index].ID)
			families[findingFamily(deduped[index].PluginID)] = true
		}
		familyNames := make([]string, 0, len(families))
		for family := range families {
			familyNames = append(familyNames, family)
		}
		sort.Strings(familyNames)
		correlations = append(correlations, model.FindingCorrelation{
			ID: id, Affected: deduped[indexes[0]].Affected,
			Family: strings.Join(familyNames, "+"), Findings: findingIDs,
			Summary: fmt.Sprintf("同一输入点关联 %d 个独立安全信号", len(indexes)),
		})
	}
	return deduped, correlations
}

func findingFamily(pluginID string) string {
	switch pluginID {
	case "sqli", "sqli_extended", "sqli_timing", "sqli_order_by", "sqli_limit", "mybatis_dynamic_sql", "nosql_injection", "ldap_injection", "xpath_injection", "command_injection", "command_injection_oast", "command_injection_timing", "ssti", "java_expression", "java_expression_extended":
		return "injection"
	case "error_disclosure", "error_disclosure_extended", "sensitive_data":
		return "disclosure"
	case "unauthorized", "idor", "csrf", "method_override", "mass_assignment", "mass_assignment_extended", "path_normalization", "parameter_confusion":
		return "authorization"
	case "reflected_xss", "cors", "crlf_injection", "open_redirect":
		return "client-boundary"
	case "file_read", "file_read_encoded", "file_upload", "file_upload_execution", "xxe", "xxe_extended", "ssrf":
		return "server-side"
	default:
		return "exposure"
	}
}
