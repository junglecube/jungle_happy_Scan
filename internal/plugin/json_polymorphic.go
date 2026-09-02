package plugin

import (
	"strings"

	"jungle_happy_Scan/internal/diff"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

// JSONPolymorphic keeps its historical ID for API/config compatibility, but
// V2.3 deliberately narrows the capability to one question: is Fastjson
// SafeMode enabled? It never tries a gadget and never infers RCE.
type JSONPolymorphic struct{}

func (JSONPolymorphic) Meta() model.PluginMeta {
	return StandardMeta("json_polymorphic", "Fastjson SafeMode 检测", "发送不存在的无害 @type，仅判断 Fastjson 是否启用 SafeMode；未启用时报告高危，不测试 RCE。", "active", true)
}

func (p JSONPolymorphic) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	rule := ctx.Rule(meta.ID)
	payloads := payloadsForMode(rule, ctx.Mode)
	patterns := compileDetectionPatterns(rule.Patterns)
	baselinePatterns := matchingPatternNames(patterns, ctx.Baselines)
	total := 0
	for _, payload := range payloads {
		total += len(jsonBindingPaths(ctx.Request.Body, payload.Group)) * 3
	}
	done := 0
	ctx.Progress(meta.ID, 0, max(total, 1))

	for _, payload := range payloads {
		token := defaultString(payload.Expected, "jungle.happy.scan.SafeModeProbe731")
		for _, fieldPath := range jsonBindingPaths(ctx.Request.Body, payload.Group) {
			request, err := httpraw.AddJSONField(ctx.Request, fieldPath, payload.Payload)
			if err != nil {
				done += 3
				ctx.Progress(meta.ID, done, max(total, 1))
				continue
			}
			first, err := ctx.Send(request)
			if err != nil {
				return nil, err
			}
			done++
			ctx.Progress(meta.ID, done, max(total, 1))
			matchOne := firstPatternRule(patterns, first.Body)

			// SafeMode's explicit rejection is the desired secure result. It is
			// not a vulnerability and must not be downgraded into an "entry"
			// finding as the historical plugin did.
			if strings.Contains(matchOne.name, "SafeMode 已开启") {
				done += 2
				ctx.Progress(meta.ID, done, max(total, 1))
				continue
			}
			if matchOne.name == "" || baselinePatterns[matchOne.name] ||
				!strings.Contains(strings.ToLower(first.Text()), strings.ToLower(token)) {
				done += 2
				ctx.Progress(meta.ID, done, max(total, 1))
				continue
			}

			control, err := ctx.Send(ctx.Request)
			if err != nil {
				return nil, err
			}
			done++
			ctx.Progress(meta.ID, done, max(total, 1))
			if firstPatternRule(patterns, control.Body).name != "" ||
				diff.Similarity(ctx.Baseline, control, ctx.Config) < 0.84 {
				done++
				ctx.Progress(meta.ID, done, max(total, 1))
				continue
			}
			second, err := ctx.Send(request)
			if err != nil {
				return nil, err
			}
			done++
			ctx.Progress(meta.ID, done, max(total, 1))
			matchTwo := firstPatternRule(patterns, second.Body)
			if matchTwo.name != matchOne.name ||
				strings.Contains(matchTwo.name, "SafeMode 已开启") ||
				!strings.Contains(strings.ToLower(second.Text()), strings.ToLower(token)) ||
				diff.Similarity(first, second, ctx.Config) < 0.90 {
				continue
			}
			return []model.Finding{Finding(meta, "Fastjson 未开启 SafeMode", model.SeverityHigh, model.ConfidenceCertain, "json:"+fieldPath,
				"无害且不存在的 @type 两次进入 Fastjson 处理流程，响应出现 Fastjson 特征，但未出现 SafeMode 的明确拒绝信息；恢复原始请求后该特征消失。结论仅表示未开启 SafeMode，不声称能够加载 gadget 或执行命令。",
				"在应用启动最早阶段启用 Fastjson SafeMode，并升级到受支持版本；使用显式 DTO，禁止信任客户端 @type。启用后应能观察到 SafeMode 对 AutoType 的明确拒绝。",
				[]model.Evidence{
					ctx.Evidence("第一次 SafeMode 探针显示未开启", request, &first, map[string]any{"payload_rule": payload.Name, "match": limitedMatch(matchOne.text), "type_token": token, "safemode_enabled": false}),
					ctx.Evidence("恢复原始请求后 Fastjson 探针特征消失", ctx.Request, &control, nil),
					ctx.Evidence("第二次重复确认未开启 SafeMode", request, &second, map[string]any{"match": limitedMatch(matchTwo.text), "safemode_enabled": false, "paired_confirmed": true}),
				}, "Fastjson SafeMode", "CWE-502")}, nil
		}
	}
	ctx.Progress(meta.ID, max(total, 1), max(total, 1))
	return nil, nil
}
