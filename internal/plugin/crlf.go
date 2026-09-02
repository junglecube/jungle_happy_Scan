package plugin

import "jungle_happy_Scan/internal/model"

type CRLFInjection struct{}

func (CRLFInjection) Meta() model.PluginMeta {
	return StandardMeta("crlf_injection", "CRLF/响应头注入", "使用唯一响应头 canary 验证输入是否能写入 HTTP 响应头。", "active", true)
}

func (p CRLFInjection) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	payloads := payloadsForMode(ctx.Rule(meta.ID), ctx.Mode)
	total := len(ctx.Points) * len(payloads)
	ctx.Progress(meta.ID, 0, max(total, 1))
	done := 0
	for _, point := range ctx.Points {
		for _, configured := range payloads {
			token := randomID("crlf")
			payload := expandPayload(configured.Payload, map[string]string{"value": point.Value, "token": token})
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
			if responseHeadersContain(response, configured.Header, token) {
				return []model.Finding{Finding(meta, "输入可注入 HTTP 响应头", model.SeverityHigh, model.ConfidenceCertain, point.Label(),
					"唯一 canary 被服务端写入独立响应头，证明 CRLF 响应头注入。",
					"拒绝 CR/LF 控制字符；不要直接将用户输入写入响应头，并使用框架安全 API。",
					[]model.Evidence{ctx.Evidence("响应出现配置的独立 canary 头", request, &response, map[string]any{"token": token, "header": configured.Header, "payload_rule": configured.Name})}, "OWASP WSTG-INPV-15")}, nil
			}
		}
	}
	return nil, nil
}
