package plugin

import (
	"net"
	"regexp"
	"strings"
	"time"

	"jungle_happy_Scan/internal/model"
)

type SensitiveData struct{}

func (SensitiveData) Meta() model.PluginMeta {
	return PassiveMeta("sensitive_data", "敏感信息泄露", "检测手机号、身份证、银行卡、邮箱、SQL、Java 堆栈、连接串、密钥、JWT、Kubernetes、Docker、路径和 IP。")
}

func (p SensitiveData) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	text := ctx.Baseline.Text()
	rule := ctx.Rule(meta.ID)
	var matches []struct {
		label      string
		value      string
		severity   model.Severity
		confidence model.Confidence
	}
	for _, configured := range rule.Patterns {
		pattern, err := regexp.Compile(configured.Pattern)
		if err != nil {
			continue
		}
		for _, match := range pattern.FindAllStringSubmatch(text, -1) {
			value := match[0]
			for _, captured := range match[1:] {
				if captured != "" {
					value = captured
					break
				}
			}
			if !validConfiguredSensitiveMatch(configured.Name, value) {
				continue
			}
			matches = append(matches, struct {
				label      string
				value      string
				severity   model.Severity
				confidence model.Confidence
			}{configured.Name, value, model.SeverityLow, confidence(configured.Confidence, model.ConfidenceFirm)})
			break
		}
	}
	ctx.Progress(meta.ID, 1, 1)
	findings := make([]model.Finding, 0, len(matches))
	for _, match := range matches {
		matched := strings.TrimSpace(match.value)
		findings = append(findings, Finding(meta, "响应泄露"+match.label, match.severity, match.confidence, "response body",
			"接口响应包含"+match.label+"。证据保留原始匹配内容，便于人工核验。",
			"根据数据类型实施访问控制、最小化返回内容，并避免在生产响应中返回敏感凭证。",
			[]model.Evidence{ctx.Evidence("匹配到 "+match.label+": "+matched, nil, &ctx.Baseline, map[string]any{"match_type": match.label})}))
	}
	return findings, nil
}

func validConfiguredSensitiveMatch(name, value string) bool {
	switch name {
	case "中国身份证号":
		return validCNID(value)
	case "银行卡号":
		return luhn(value)
	case "IP 地址":
		return net.ParseIP(value) != nil
	default:
		return true
	}
}

func validCNID(value string) bool {
	if len(value) != 18 {
		return false
	}
	if _, err := time.Parse("20060102", value[6:14]); err != nil {
		return false
	}
	weights := []int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	checks := "10X98765432"
	total := 0
	for i := 0; i < 17; i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
		total += int(value[i]-'0') * weights[i]
	}
	return checks[total%11] == strings.ToUpper(value[17:])[0]
}

func luhn(value string) bool {
	total := 0
	parity := len(value) % 2
	for i := range value {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
		digit := int(value[i] - '0')
		if i%2 == parity {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		total += digit
	}
	return total%10 == 0
}
