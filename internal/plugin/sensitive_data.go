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
	return PassiveMeta("sensitive_data", "敏感信息泄露", "检测 Flag 标记、手机号、身份证、银行卡、邮箱、SQL、Java 堆栈、连接串、密钥、JWT、Kubernetes、Docker、路径和 IP。")
}

func (p SensitiveData) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	text := ctx.Baseline.Text()
	rule := ctx.Rule(meta.ID)
	var findings []model.Finding
	for _, configured := range rule.Patterns {
		pattern, err := regexp.Compile(configured.Pattern)
		if err != nil {
			continue
		}
		samples := []string{}
		seen := map[string]bool{}
		count := 0
		rawMatches := pattern.FindAllStringSubmatch(text, 10001)
		for _, match := range rawMatches[:min(10000, len(rawMatches))] {
			value := match[0]
			for _, captured := range match[1:] {
				if captured != "" {
					value = captured
					break
				}
			}
			validator := configured.Validator
			if validator == "" {
				validator = configured.Name
			}
			if !validConfiguredSensitiveMatch(validator, value) {
				continue
			}
<<<<<<< HEAD
			count++
			if len(samples) < 5 && !seen[value] {
				samples = append(samples, value)
				seen[value] = true
			}
=======
			matches = append(matches, struct {
				label      string
				value      string
				severity   model.Severity
				confidence model.Confidence
			}{configured.Name, value, model.ParseSeverity(configured.Severity, model.SeverityLow), confidence(configured.Confidence, model.ConfidenceFirm)})
			break
>>>>>>> 7e660119acdb144ab49f86bcfe0d35e79c6f9929
		}
		if count == 0 {
			continue
		}
		findings = append(findings, Finding(meta, "响应包含"+configured.Name, model.ParseSeverity(configured.Severity, model.SeverityLow), confidence(configured.Confidence, model.ConfidenceFirm), "response body",
			"发现敏感格式内容；需结合数据归属、公开用途和接口权限判断是否属于泄露，格式命中本身不证明越权。",
			"按业务权限最小化返回数据；凭证类内容应避免进入响应。",
			[]model.Evidence{ctx.Evidence("匹配到 "+configured.Name+": "+samples[0], nil, &ctx.Baseline, map[string]any{"match": samples[0], "match_type": configured.Name, "match_count": count, "samples": samples, "count_capped": len(rawMatches) > 10000, "validator": configured.Validator})}))
	}
	ctx.Progress(meta.ID, 1, 1)
	return findings, nil
}

func validConfiguredSensitiveMatch(name, value string) bool {
	switch name {
	case "中国身份证号", "cn_id":
		return validCNID(value)
	case "银行卡号", "luhn":
		return luhn(value)
	case "IP 地址", "ip":
		return net.ParseIP(value) != nil
	default:
		return true
	}
}

func validCNID(value string) bool {
	if len(value) != 18 {
		return false
	}
	// The configured regexp performs the cheap shape/date-range prefilter; keep
	// this guard here as well for custom callers and persisted legacy rules.
	if value[6:10] < "1900" || value[6:10] > "2030" {
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
	if len(value) < 16 || len(value) > 19 || allSameDigits(value) {
		return false
	}
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

func allSameDigits(value string) bool {
	if len(value) == 0 {
		return false
	}
	for i := 1; i < len(value); i++ {
		if value[i] != value[0] {
			return false
		}
	}
	return true
}
