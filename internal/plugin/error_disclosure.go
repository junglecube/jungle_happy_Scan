package plugin

import (
	"strings"

	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/model"
)

type ErrorDisclosure struct{}

func (ErrorDisclosure) Meta() model.PluginMeta {
	return StandardMeta("error_disclosure", "输入诱导异常信息泄露", "主动变异参数并重复确认仅在异常输入下出现的 Java、Spring、ORM、SQL、路径或调试信息。", "active", true)
}

func (p ErrorDisclosure) Scan(ctx *Context) ([]model.Finding, error) {
	return scanErrorDisclosure(ctx, p.Meta())
}

func scanErrorDisclosure(ctx *Context, meta model.PluginMeta) ([]model.Finding, error) {
	rule := ctx.Rule(meta.ID)
	payloads := payloadsForMode(rule, ctx.Mode)
	if meta.ID == "error_disclosure" {
		payloads = coreErrorDisclosurePayload(payloads)
	}
	patterns := compileDetectionPatterns(rule.Patterns)
	baselinePatterns := matchingPatternNames(patterns, ctx.Baselines)
	total := len(ctx.Points) * len(payloads) * 3
	done := 0
	ctx.Progress(meta.ID, 0, max(total, 1))
	var findings []model.Finding
	for _, point := range ctx.Points {
		confirmed := false
		for _, payload := range payloads {
			value := expandPayload(payload.Payload, map[string]string{"value": point.Value})
			requestOne, err := ctx.Mutate(point, value)
			if err != nil {
				done += 3
				ctx.Progress(meta.ID, done, total)
				continue
			}
			responseOne, err := ctx.Send(requestOne)
			if err != nil {
				return findings, err
			}
			done++
			matchOne := firstPatternRule(patterns, responseOne.Body)
			if matchOne.name == "" || baselinePatterns[matchOne.name] {
				done += 2
				ctx.Progress(meta.ID, done, total)
				continue
			}
			control, err := ctx.Send(ctx.Request)
			if err != nil {
				return findings, err
			}
			done++
			if firstPatternRule(patterns, control.Body).name != "" {
				done++
				ctx.Progress(meta.ID, done, total)
				continue
			}
			responseTwo, err := ctx.Send(requestOne)
			if err != nil {
				return findings, err
			}
			done++
			ctx.Progress(meta.ID, done, total)
			matchTwo := firstPatternRule(patterns, responseTwo.Body)
			if matchTwo.name == "" || matchTwo.name != matchOne.name {
				continue
			}
			severityValue, confidenceValue := matchOne.severityConfidence()
			findings = append(findings, Finding(meta, "异常输入触发"+matchOne.name, severityValue, confidenceValue, point.Label(),
				"相同异常 Payload 两次稳定触发"+matchOne.name+"，恢复原始请求后泄露特征消失。该结果说明服务端将内部异常或调试细节返回给了调用方。",
				"统一异常处理并返回固定业务错误；生产环境关闭堆栈和 SQL 输出；日志仅写入受控服务端并对路径、凭据及数据脱敏。",
				[]model.Evidence{
					ctx.Evidence("第一次异常输入触发 "+matchOne.name, requestOne, &responseOne, map[string]any{"payload_rule": payload.Name, "match": limitedMatch(matchOne.text)}),
					ctx.Evidence("恢复原始值后异常信息消失", ctx.Request, &control, nil),
					ctx.Evidence("第二次异常输入重复触发 "+matchTwo.name, requestOne, &responseTwo, map[string]any{"match": limitedMatch(matchTwo.text)}),
				}, "CWE-209"))
			confirmed = true
			break
		}
		if confirmed {
			remaining := len(payloads)*3 - (done % max(len(payloads)*3, 1))
			if remaining < len(payloads)*3 {
				done += remaining
				ctx.Progress(meta.ID, min(done, total), total)
			}
		}
	}
	return findings, nil
}

func coreErrorDisclosurePayload(payloads []config.PayloadRule) []config.PayloadRule {
	for _, payload := range payloads {
		if payload.Name == "单引号异常" {
			return []config.PayloadRule{payload}
		}
	}
	if len(payloads) > 0 {
		return payloads[:1]
	}
	return nil
}

func limitedMatch(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 240 {
		return value[:240] + "..."
	}
	return value
}

func matchingPatternNames(patterns []compiledPattern, responses []model.Response) map[string]bool {
	result := make(map[string]bool)
	for _, response := range responses {
		for _, pattern := range patterns {
			if pattern.re.Match(response.Body) {
				result[pattern.rule.Name] = true
			}
		}
	}
	return result
}
