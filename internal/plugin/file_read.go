package plugin

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"

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
		if fileReadPoint(point, rule.ParameterNames) {
			points = append(points, point)
		}
	}
	payloads := payloadsForMode(rule, ctx.Mode)
	total := len(points) * len(payloads) * 3
	done := 0
	ctx.Progress(meta.ID, done, max(total, 1))
	var findings []model.Finding
	for _, point := range points {
		for _, payload := range payloads {
			expected, err := regexp.Compile(payload.Expected)
			if err != nil || payload.Expected == "" {
				done += 3
				ctx.Progress(meta.ID, done, total)
				continue
			}
			request, err := ctx.Mutate(point, expandPayload(payload.Payload, map[string]string{"value": point.Value}))
			if err != nil {
				done += 3
				ctx.Progress(meta.ID, done, total)
				continue
			}
			first, err := ctx.Send(request)
			if err != nil {
				return findings, err
			}
			done++
			ctx.Progress(meta.ID, done, total)
			firstMatch := fileResponseMatch(expected, first.Body)
			if len(firstMatch) == 0 || len(fileResponseMatch(expected, ctx.Baseline.Body)) > 0 {
				done += 2
				ctx.Progress(meta.ID, done, total)
				continue
			}
			negativeReq, err := ctx.Mutate(point, expandPayload(payload.Payload, map[string]string{"value": point.Value})+"."+randomID("missing"))
			if err != nil {
				ctx.ResolveMutationFailed(2)
				done += 2
				continue
			}
			negative, err := ctx.Send(negativeReq)
			if err != nil {
				return findings, err
			}
			done++
			if len(fileResponseMatch(expected, negative.Body)) > 0 {
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
			secondMatch := fileResponseMatch(expected, second.Body)
			if len(secondMatch) == 0 {
				continue
			}
			findings = append(findings, Finding(meta, "任意文件读取/路径穿越", model.SeverityHigh, model.ConfidenceCertain, point.Label(),
				"同一路径两次出现基线及随机不存在路径对照均未出现的 Linux 文件指纹；支持 JSON 字符串及 Base64 内容。",
				"使用服务端资源 ID 映射；规范化并解析符号链接后确保真实路径位于固定目录，拒绝绝对路径、URI Scheme 和编码穿越，并以最小权限运行服务。",
				[]model.Evidence{
					ctx.Evidence("首次响应匹配文件读取规则 "+payload.Name, request, &first, map[string]any{"match": string(firstMatch), "payload_rule": payload.Name}),
					ctx.Evidence("第二次重复确认相同文件指纹", request, &second, map[string]any{"match": string(secondMatch), "payload_rule": payload.Name}),
					ctx.Evidence("随机不存在路径未出现文件指纹", negativeReq, &negative, map[string]any{"negative_control": true}),
				}, "OWASP WSTG-ATHZ-01"))
			break
		}
	}
	ctx.Progress(meta.ID, total, max(total, 1))
	return findings, nil
}

func fileReadPoint(point httpraw.InsertionPoint, names []string) bool {
	value := strings.TrimSpace(point.Value)
	return semanticName(point.Name, names) || strings.HasPrefix(value, "/") || strings.HasPrefix(value, "./") || strings.HasPrefix(value, "../") || strings.HasPrefix(value, "file://") || strings.Contains(value, "/") && !strings.Contains(value, "://")
}
func fileResponseMatch(pattern *regexp.Regexp, body []byte) []byte {
	if match := pattern.Find(body); len(match) > 0 {
		return match
	}
	var value any
	if json.Unmarshal(body, &value) == nil {
		return fileValueMatch(pattern, value, 0)
	}
	return decodedFileMatch(pattern, string(body))
}
func decodedFileMatch(pattern *regexp.Regexp, value string) []byte {
	if len(value) > 2_000_000 {
		return nil
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if decoded, err := encoding.DecodeString(strings.TrimSpace(value)); err == nil {
			if match := pattern.Find(decoded); len(match) > 0 {
				return match
			}
		}
	}
	return nil
}
func fileValueMatch(pattern *regexp.Regexp, value any, depth int) []byte {
	if depth > 10 {
		return nil
	}
	switch v := value.(type) {
	case string:
		if match := pattern.FindString(v); match != "" {
			return []byte(match)
		}
		return decodedFileMatch(pattern, v)
	case map[string]any:
		for _, child := range v {
			if match := fileValueMatch(pattern, child, depth+1); len(match) > 0 {
				return match
			}
		}
	case []any:
		for _, child := range v {
			if match := fileValueMatch(pattern, child, depth+1); len(match) > 0 {
				return match
			}
		}
	}
	return nil
}
