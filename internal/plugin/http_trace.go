package plugin

import (
	"strings"

	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

type HTTPTrace struct{}

func (HTTPTrace) Meta() model.PluginMeta {
	return StandardMeta("http_trace", "HTTP TRACE 方法开放", "发送不含会话的 TRACE 请求，仅在唯一请求头被响应体原样回显时确认。", "active", true)
}

func (p HTTPTrace) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	token := randomID("trace")
	request, _ := httpraw.RemoveSessions(ctx.Request, httpraw.EffectiveSessionIdentifiers(ctx.Request, ctx.Config.SessionIdentifiers))
	request.Method = "TRACE"
	request = request.WithBody(nil).WithoutHeaders("Content-Type", "Content-Length")
	request = request.WithHeader("X-Jungle-Trace", token)
	ctx.Progress(meta.ID, 0, 1)
	response, err := ctx.Send(request)
	if err != nil {
		return nil, err
	}
	ctx.Progress(meta.ID, 1, 1)
	text := strings.ToLower(response.Text())
	if !strings.Contains(text, strings.ToLower("X-Jungle-Trace: "+token)) {
		return nil, nil
	}
	return []model.Finding{Finding(meta, "服务器开放 TRACE 并回显请求头", model.SeverityMedium, model.ConfidenceCertain, "method:TRACE",
		"TRACE 响应体原样包含唯一测试请求头，确认服务器启用了请求回显。",
		"在反向代理、Servlet 容器和应用服务器禁用 TRACE；同时使用 HttpOnly/SameSite Cookie 降低浏览器侧风险。",
		[]model.Evidence{ctx.Evidence("TRACE 响应回显唯一请求头", request, &response, map[string]any{"match": token, "evidence_strength": "L3"})}, "CWE-693")}, nil
}
