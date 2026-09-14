package diff

import (
	"encoding/json"
	"fmt"
	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/model"
	"regexp"
	"strconv"
	"strings"
)

type Outcome string

const (
	Unknown Outcome = "unknown"
	Success Outcome = "success"
	Failure Outcome = "failure"
)

type BusinessResult struct {
	Outcome Outcome
	Rule    string
}

// EvaluateBusiness never treats transport success as business success. Explicit
// failure (including a scoped custom rule) wins across all matched rules.
func EvaluateBusiness(r model.Response, cfg config.Config, pluginID, target string) BusinessResult {
	result := BusinessResult{Outcome: Unknown}
	if r.StatusCode < 200 || r.StatusCode >= 300 || LikelyAuthDenied(r, cfg) {
		return BusinessResult{Failure, "http/auth"}
	}
	var root any
	decoder := json.NewDecoder(strings.NewReader(string(r.Body)))
	decoder.UseNumber()
	_ = decoder.Decode(&root)
	for _, rule := range cfg.BusinessRules {
		if len(rule.PluginIDs) > 0 {
			ok := false
			for _, id := range rule.PluginIDs {
				if id == pluginID {
					ok = true
				}
			}
			if !ok {
				continue
			}
		}
		if rule.URLPattern != "" && !businessRegex(rule.URLPattern, target) {
			continue
		}
		if len(rule.StatusCodes) > 0 {
			ok := false
			for _, code := range rule.StatusCodes {
				if code == r.StatusCode {
					ok = true
				}
			}
			if !ok {
				continue
			}
		}
		text := string(r.Body)
		if rule.JSONPath != "" {
			value, ok := businessPath(root, rule.JSONPath)
			if !ok {
				continue
			}
			text = fmt.Sprint(value)
		}
		if rule.Equals != nil && text != *rule.Equals {
			continue
		}
		if rule.Pattern != "" && !businessRegex(rule.Pattern, text) {
			continue
		}
		if rule.Outcome == "failure" {
			return BusinessResult{Failure, rule.Name}
		}
		result = BusinessResult{Success, rule.Name}
	}
	// Only outcome envelopes are inspected: data records' code/status fields are
	// not response status. Custom JSON paths cover nonstandard envelopes.
	built := envelopeOutcome(root, 0)
	if built == Failure && (result.Outcome != Success || envelopeExplicitFailure(root, 0)) {
		return BusinessResult{Failure, "structured_failure"}
	}
	if result.Outcome == Success {
		return result
	}
	if built == Success {
		return BusinessResult{Success, "structured_success"}
	}
	for _, pattern := range cfg.SuccessPatterns {
		if root != nil && genericLegacySuccessPattern(pattern) {
			continue
		}
		if businessRegex(pattern, string(r.Body)) {
			return BusinessResult{Success, "legacy_success_pattern"}
		}
	}
	return result
}
func businessRegex(pattern, text string) bool {
	re, err := regexp.Compile(pattern)
	return err == nil && re.MatchString(text)
}
func envelopeOutcome(root any, depth int) Outcome {
	if depth > 4 {
		return Unknown
	}
	m, ok := root.(map[string]any)
	if !ok {
		return Unknown
	}
	result := Unknown
	for key, value := range m {
		switch strings.ToLower(key) {
		case "success", "successful":
			if b, ok := value.(bool); ok {
				if !b {
					return Failure
				}
				result = Success
			}
		case "code", "status", "statuscode", "resultcode", "retcode":
			text := fmt.Sprint(value)
			if text == "0" || text == "200" || text == "000000" {
				result = Success
			} else if n, err := strconv.Atoi(text); err == nil && n != 0 && n != 200 {
				return Failure
			}
		case "msg", "message", "resultmsg", "resultmessage", "error":
			text := strings.ToLower(fmt.Sprint(value))
			if businessRegex(`失败|频繁|稍后|错误|不允许|不支持|拒绝|invalid|too\s*many|limit|failed|failure|denied|not\s+allowed`, text) {
				return Failure
			}
			if strings.Contains(text, "发送成功") || strings.Contains(text, "下发成功") || strings.Contains(text, "上传成功") {
				result = Success
			}
		case "result", "response":
			if child := envelopeOutcome(value, depth+1); child == Failure {
				return Failure
			} else if child == Success {
				result = Success
			}
		}
	}
	return result
}

var pathToken = regexp.MustCompile(`\.([A-Za-z_][A-Za-z0-9_-]*)|\[([0-9]+)\]`)

func businessPath(root any, path string) (any, bool) {
	if path == "$" {
		return root, root != nil
	}
	value := root
	for _, part := range pathToken.FindAllStringSubmatch(path, -1) {
		if part[1] != "" {
			m, ok := value.(map[string]any)
			if !ok {
				return nil, false
			}
			value, ok = m[part[1]]
			if !ok {
				return nil, false
			}
		} else {
			a, ok := value.([]any)
			i, err := strconv.Atoi(part[2])
			if !ok || err != nil || i >= len(a) {
				return nil, false
			}
			value = a[i]
		}
	}
	return value, true
}

func ScopedBusinessRules(rules []config.BusinessRule, pluginID, target string) []config.BusinessRule {
	var result []config.BusinessRule
	for _, rule := range rules {
		if len(rule.PluginIDs) > 0 {
			matched := false
			for _, id := range rule.PluginIDs {
				if id == pluginID {
					matched = true
				}
			}
			if !matched {
				continue
			}
		}
		if rule.URLPattern != "" && !businessRegex(rule.URLPattern, target) {
			continue
		}
		rule.PluginIDs = nil
		rule.URLPattern = ""
		result = append(result, rule)
	}
	return result
}
func envelopeExplicitFailure(root any, depth int) bool {
	if depth > 4 {
		return false
	}
	m, ok := root.(map[string]any)
	if !ok {
		return false
	}
	for key, value := range m {
		switch strings.ToLower(key) {
		case "success", "successful":
			if b, ok := value.(bool); ok && !b {
				return true
			}
		case "msg", "message", "resultmsg", "resultmessage", "error":
			if businessRegex(`失败|频繁|稍后|错误|不允许|不支持|拒绝|invalid|too\s*many|limit|failed|failure|denied|not\s+allowed`, strings.ToLower(fmt.Sprint(value))) {
				return true
			}
		case "result", "response":
			if envelopeExplicitFailure(value, depth+1) {
				return true
			}
		}
	}
	return false
}

var legacyGenericPatterns = config.Default().SuccessPatterns

func genericLegacySuccessPattern(pattern string) bool {
	defaults := legacyGenericPatterns
	for _, p := range defaults[:min(2, len(defaults))] {
		if p == pattern {
			return true
		}
	}
	return false
}
