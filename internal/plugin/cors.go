package plugin

import (
	"strings"

	"jungle_happy_Scan/internal/model"
)

type CORS struct{}

func (CORS) Meta() model.PluginMeta {
	return StandardMeta("cors", "CORS 配置错误", "验证任意 Origin 反射、凭证跨域、null Origin 和域名后缀绕过。", "active", true)
}

func (p CORS) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	payloads := payloadsForMode(ctx.Rule(meta.ID), ctx.Mode)
	origins := make([]string, 0, len(payloads))
	for _, payload := range payloads {
		origins = append(origins, expandPayload(payload.Payload, map[string]string{"host": ctx.Request.Host()}))
	}
	ctx.Progress(meta.ID, 0, len(origins))
	for index, origin := range origins {
		request := ctx.Request.WithHeader("Origin", origin)
		response, err := ctx.Send(request)
		if err != nil {
			return nil, err
		}
		ctx.Progress(meta.ID, index+1, len(origins))
		acao := strings.TrimSpace(response.Header("Access-Control-Allow-Origin"))
		credentials := strings.EqualFold(strings.TrimSpace(response.Header("Access-Control-Allow-Credentials")), "true")
		if acao == origin && credentials {
			title := "CORS 允许不可信源携带凭证读取响应"
			confidence := model.ConfidenceCertain
			if origin == "null" {
				title = "CORS 信任 null Origin 并允许凭证"
				confidence = model.ConfidenceFirm
			}
			return []model.Finding{Finding(meta, title, model.SeverityHigh, confidence, "header:Origin",
				"服务端允许攻击者控制的 Origin，并同时允许浏览器携带用户凭证读取响应。",
				"使用完整、精确的 Origin 白名单；不要反射任意 Origin，敏感接口禁止跨域凭证。",
				[]model.Evidence{ctx.Evidence("不可信 Origin 被允许且 Access-Control-Allow-Credentials 为 true", request, &response, map[string]any{"origin": origin, "acao": acao, "credentials": credentials})},
				"OWASP WSTG-CLNT-07")}, nil
		}
		if acao == "*" && len(response.Body) > 0 {
			return []model.Finding{Finding(meta, "CORS 对任意来源开放响应", model.SeverityInfo, model.ConfidenceTentative, "response headers",
				"接口返回 Access-Control-Allow-Origin: *。这对公开资源通常是正常配置；只有响应包含无需 Cookie 即可读取的敏感数据时才构成安全问题，需结合业务人工确认。",
				"对敏感接口使用精确 Origin 白名单；公开数据接口需确认返回内容确实可公开。",
				[]model.Evidence{ctx.Evidence("响应允许任意 Origin", request, &response, map[string]any{"acao": "*"})}, "OWASP WSTG-CLNT-07")}, nil
		}
	}
	return nil, nil
}
