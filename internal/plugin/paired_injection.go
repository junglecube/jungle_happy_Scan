package plugin

import (
	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/diff"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

type injectionMutator func(*Context, httpraw.InsertionPoint, string) (*httpraw.Request, error)

func scanPairedInjection(
	ctx *Context,
	meta model.PluginMeta,
	mutate injectionMutator,
	title, description, remediation, reference string,
) ([]model.Finding, error) {
	rule := ctx.Rule(meta.ID)
	payloads := payloadsForMode(rule, ctx.Mode)
	pairs := pairPayloads(payloads, "boolean_true", "boolean_false")
	errorPayloads := make([]config.PayloadRule, 0)
	for _, payload := range payloads {
		if payload.Kind == "error_probe" {
			errorPayloads = append(errorPayloads, payload)
		}
	}
	patterns := compileDetectionPatterns(rule.Patterns)
	baselinePatterns := matchingPatternNames(patterns, ctx.Baselines)
	totalPerPoint := len(errorPayloads)*2 + len(pairs)*4
	total := len(ctx.Points) * totalPerPoint
	done := 0
	ctx.Progress(meta.ID, 0, max(total, 1))
	var findings []model.Finding
	for _, point := range ctx.Points {
		found := false
		for _, payload := range errorPayloads {
			request, err := mutate(ctx, point, expandPayload(payload.Payload, map[string]string{"value": point.Value}))
			if err != nil {
				done += 2
				continue
			}
			first, err := ctx.Send(request)
			if err != nil {
				return findings, err
			}
			done++
			matchOne := firstPatternRule(patterns, first.Body)
			if matchOne.name == "" || baselinePatterns[matchOne.name] {
				done++
				ctx.Progress(meta.ID, done, total)
				continue
			}
			second, err := ctx.Send(request)
			if err != nil {
				return findings, err
			}
			done++
			ctx.Progress(meta.ID, done, total)
			matchTwo := firstPatternRule(patterns, second.Body)
			if matchTwo.name != matchOne.name {
				continue
			}
			severityValue, confidenceValue := matchOne.severityConfidence()
			findings = append(findings, Finding(meta, title+"（错误特征）", severityValue, confidenceValue, point.Label(),
				"两次相同探测均触发"+matchOne.name+"，原始响应不存在该特征。"+description,
				remediation,
				[]model.Evidence{
					ctx.Evidence("第一次触发 "+matchOne.name, request, &first, map[string]any{"payload_rule": payload.Name, "match": limitedMatch(matchOne.text)}),
					ctx.Evidence("第二次重复触发 "+matchTwo.name, request, &second, map[string]any{"match": limitedMatch(matchTwo.text)}),
				}, reference))
			found = true
			break
		}
		if !found && diff.BaselineStability(ctx.Baselines, ctx.Config) >= 0.85 {
			for _, pair := range pairs {
				rules := []config.PayloadRule{pair.left, pair.right, pair.right, pair.left}
				requests := make([]*httpraw.Request, 0, 4)
				responses := make([]model.Response, 0, 4)
				valid := true
				for _, payload := range rules {
					request, err := mutate(ctx, point, expandPayload(payload.Payload, map[string]string{"value": point.Value}))
					if err != nil {
						valid = false
						break
					}
					requests = append(requests, request)
					response, err := ctx.Send(request)
					if err != nil {
						return findings, err
					}
					responses = append(responses, response)
					done++
					ctx.Progress(meta.ID, done, total)
				}
				if !valid || len(responses) != 4 || !validDifferentialResponses(ctx, responses) {
					continue
				}
				t1 := diff.Similarity(ctx.Baseline, responses[0], ctx.Config)
				f1 := diff.Similarity(ctx.Baseline, responses[1], ctx.Config)
				f2 := diff.Similarity(ctx.Baseline, responses[2], ctx.Config)
				t2 := diff.Similarity(ctx.Baseline, responses[3], ctx.Config)
				if t1 >= 0.86 && t2 >= 0.86 && f1 <= 0.74 && f2 <= 0.74 &&
					min(t1-f1, t2-f2) >= 0.18 &&
					diff.Similarity(responses[0], responses[3], ctx.Config) >= 0.90 &&
					diff.Similarity(responses[1], responses[2], ctx.Config) >= 0.90 {
					findings = append(findings, Finding(meta, title+"（布尔差分）", model.SeverityHigh, model.ConfidenceCertain, point.Label(),
						"逻辑真条件两次接近原始响应，逻辑假条件两次稳定偏离，且第二轮采用反向顺序确认。"+description,
						remediation,
						[]model.Evidence{
							ctx.Evidence("第一轮逻辑真", requests[0], &responses[0], map[string]any{"similarity": t1, "group": pair.group}),
							ctx.Evidence("第一轮逻辑假", requests[1], &responses[1], map[string]any{"similarity": f1}),
							ctx.Evidence("反向复核逻辑假", requests[2], &responses[2], map[string]any{"similarity": f2}),
							ctx.Evidence("反向复核逻辑真", requests[3], &responses[3], map[string]any{"similarity": t2}),
						}, reference))
					found = true
					break
				}
			}
		}
	}
	ctx.Progress(meta.ID, max(done, total), max(total, 1))
	return findings, nil
}
