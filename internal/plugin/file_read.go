package plugin

import (
	"regexp"

	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

type FileRead struct{}

func (FileRead) Meta() model.PluginMeta {
	return StandardMeta("file_read", "任意文件读取", "使用前台配置的参数名、路径 payload 和响应指纹检测文件读取。", "active", true)
}

func (p FileRead) Scan(ctx *Context) ([]model.Finding, error) {
	return scanFileRead(ctx, p.Meta())
}

func scanFileRead(ctx *Context, meta model.PluginMeta) ([]model.Finding, error) {
	rule := ctx.Rule(meta.ID)
	points := make([]httpraw.InsertionPoint, 0, len(ctx.Points))
	for _, point := range ctx.Points {
		if semanticName(point.Name, rule.ParameterNames) {
			points = append(points, point)
		}
	}
	payloads := payloadsForMode(rule, ctx.Mode)
	total := len(points) * len(payloads) * 2
	done := 0
	ctx.Progress(meta.ID, done, max(total, 1))
	var findings []model.Finding
	for _, point := range points {
		for _, payload := range payloads {
			expected, err := regexp.Compile(payload.Expected)
			if err != nil || payload.Expected == "" {
				done += 2
				ctx.Progress(meta.ID, done, total)
				continue
			}
			request, err := ctx.Mutate(point, expandPayload(payload.Payload, map[string]string{"value": point.Value}))
			if err != nil {
				done += 2
				ctx.Progress(meta.ID, done, total)
				continue
			}
			first, err := ctx.Send(request)
			if err != nil {
				return findings, err
			}
			done++
			ctx.Progress(meta.ID, done, total)
			firstMatch := expected.Find(first.Body)
			if len(firstMatch) == 0 || expected.Match(ctx.Baseline.Body) {
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
			secondMatch := expected.Find(second.Body)
			if len(secondMatch) == 0 {
				continue
			}
			findings = append(findings, Finding(meta, "任意文件读取/路径穿越", model.SeverityHigh, model.ConfidenceCertain, point.Label(),
				"同一路径 Payload 连续两次使响应出现基线不存在的 Linux 系统文件强指纹。",
				"使用服务端资源 ID 映射；规范化并解析符号链接后确保真实路径位于固定目录，拒绝绝对路径、URI Scheme 和编码穿越，并以最小权限运行服务。",
				[]model.Evidence{
					ctx.Evidence("首次响应匹配文件读取规则 "+payload.Name, request, &first, map[string]any{"match": string(firstMatch), "payload_rule": payload.Name}),
					ctx.Evidence("第二次重复确认相同文件指纹", request, &second, map[string]any{"match": string(secondMatch), "payload_rule": payload.Name}),
				}, "OWASP WSTG-ATHZ-01"))
			break
		}
	}
	ctx.Progress(meta.ID, total, max(total, 1))
	return findings, nil
}
