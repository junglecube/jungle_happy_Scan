package config

import (
	"fmt"
	"regexp"
	"strings"
)

func upgradeV39(c *Config) {
	if c.SMS.Attempts == 0 {
		c.SMS = SMSConfig{30, 5, 60}
	}
	if c.CallbackWaitSeconds == 0 {
		c.CallbackWaitSeconds = 8
	}
	if c.CallbackLateSeconds == 0 {
		c.CallbackLateSeconds = 120
	}
	if c.BusinessRules == nil {
		c.BusinessRules = []BusinessRule{}
	}
	rule := c.PluginRules["sensitive_data"]
	for i := range rule.Patterns {
		if rule.Patterns[i].Validator == "" {
			rule.Patterns[i].Validator = legacyValidator(rule.Patterns[i].Name)
		}
	}
	c.PluginRules["sensitive_data"] = rule
}
func legacyValidator(name string) string {
	switch name {
	case "中国身份证号":
		return "cn_id"
	case "银行卡号":
		return "luhn"
	case "IP 地址":
		return "ip"
	}
	return ""
}
func validateV39(c Config) error {
	if c.SMS.Attempts < 1 || c.SMS.Attempts > 100 || c.SMS.Threshold < 1 || c.SMS.Threshold >= c.SMS.Attempts || c.SMS.WindowSeconds < 1 || c.SMS.WindowSeconds > 300 {
		return fmt.Errorf("sms: attempts 2–100，threshold 小于 attempts，window_seconds 1–300")
	}
	if c.CallbackWaitSeconds < 0 || c.CallbackWaitSeconds > 60 || c.CallbackLateSeconds < 0 || c.CallbackLateSeconds > 600 {
		return fmt.Errorf("回连同步等待必须为 0–60 秒，迟到窗口为 0–600 秒")
	}
	if len(c.BusinessRules) > 200 {
		return fmt.Errorf("业务规则最多 200 条")
	}
	for _, r := range c.BusinessRules {
		if strings.TrimSpace(r.Name) == "" || (r.Outcome != "success" && r.Outcome != "failure") {
			return fmt.Errorf("业务规则需要 name 和 success/failure outcome")
		}
		if len(r.StatusCodes) == 0 && r.Pattern == "" && r.Equals == nil {
			return fmt.Errorf("业务规则 %s 缺少条件", r.Name)
		}
		if r.Equals != nil && r.JSONPath == "" {
			return fmt.Errorf("业务规则 %s: equals 需要 json_path", r.Name)
		}
		if r.JSONPath != "" && r.Equals == nil && r.Pattern == "" {
			return fmt.Errorf("业务规则 %s: json_path 需要 equals 或 pattern", r.Name)
		}
		if r.JSONPath != "" && !regexp.MustCompile(`^\$(?:\.[A-Za-z_][A-Za-z0-9_-]*|\[[0-9]+\])*$`).MatchString(r.JSONPath) {
			return fmt.Errorf("业务规则 %s: JSON 路径仅支持 $.data.code 和数组下标", r.Name)
		}
		for _, p := range []string{r.URLPattern, r.Pattern} {
			if len(p) > 4096 {
				return fmt.Errorf("业务规则正则过长")
			}
			if _, err := regexp.Compile(p); err != nil {
				return fmt.Errorf("业务规则 %s: %w", r.Name, err)
			}
		}
		for _, code := range r.StatusCodes {
			if code < 100 || code > 599 {
				return fmt.Errorf("业务规则状态码无效")
			}
		}
	}
	for _, rule := range c.PluginRules {
		for _, p := range rule.Patterns {
			switch p.Validator {
			case "", "none", "cn_id", "luhn", "ip":
			default:
				return fmt.Errorf("未知敏感信息 validator: %s", p.Validator)
			}
		}
	}
	return nil
}
