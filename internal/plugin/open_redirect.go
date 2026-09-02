package plugin

import (
	"net/url"
	"strings"

	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

type OpenRedirect struct{}

func (OpenRedirect) Meta() model.PluginMeta {
	return StandardMeta("open_redirect", "开放重定向", "使用前台配置的参数名和外部 URL payload 验证跨站 Location。", "active", true)
}

func (p OpenRedirect) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	rule := ctx.Rule(meta.ID)
	var points []httpraw.InsertionPoint
	for _, point := range ctx.Points {
		if semanticName(point.Name, rule.ParameterNames) {
			points = append(points, point)
		}
	}
	payloads := payloadsForMode(rule, ctx.Mode)
	total := len(points) * len(payloads)
	ctx.Progress(meta.ID, 0, max(total, 1))
	done := 0
	for _, point := range points {
		for _, configured := range payloads {
			token := randomID("redirect")
			payload := expandPayload(configured.Payload, map[string]string{"token": token, "value": point.Value, "host": ctx.Request.Host()})
			request, err := ctx.Mutate(point, payload)
			if err != nil {
				continue
			}
			response, err := ctx.Send(request)
			if err != nil {
				return nil, err
			}
			done++
			ctx.Progress(meta.ID, done, total)
			location := response.Header("Location")
			parsed, parseErr := url.Parse(location)
			expected, expectedErr := url.Parse(payload)
			if parseErr == nil && expectedErr == nil && strings.EqualFold(parsed.Hostname(), expected.Hostname()) && strings.Contains(location, token) {
				return []model.Finding{Finding(meta, "用户输入可控制跨站重定向", model.SeverityMedium, model.ConfidenceCertain, point.Label(),
					"响应 Location 精确跳转到配置的外部域名并保留唯一 token。",
					"只允许相对路径或使用严格目的地白名单；解析并规范化 URL 后再校验。",
					[]model.Evidence{ctx.Evidence("Location 指向外部验证域名", request, &response, map[string]any{"location": location, "payload_rule": configured.Name})}, "OWASP WSTG-CLNT-04")}, nil
			}
		}
	}
	return nil, nil
}
