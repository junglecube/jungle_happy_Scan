package plugin

import (
	"strings"
	"time"

	"jungle_happy_Scan/internal/callback"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

type SSRF struct{}

func (SSRF) Meta() model.PluginMeta {
	return StandardMeta("ssrf", "SSRF", "向配置的 URL 类参数注入回连 payload，支持同步响应与离线回连确认。", "active", true)
}

func (p SSRF) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	if ctx.Config.CallbackBaseURL == "" {
		ctx.Progress(meta.ID, 1, 1)
		return nil, nil
	}
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
	var findings []model.Finding
	type callbackProbe struct {
		token    string
		point    httpraw.InsertionPoint
		rule     string
		request  *httpraw.Request
		response model.Response
		marker   string
		inBand   bool
	}
	var pending []callbackProbe
	for _, point := range points {
		for _, payload := range payloads {
			token, callbackURL := ctx.Callbacks.Register(ctx.Config.CallbackBaseURL, "ssrf")
			value := expandPayload(payload.Payload, map[string]string{"callback": callbackURL, "token": token, "value": point.Value})
			request, err := ctx.Mutate(point, value)
			if err != nil {
				continue
			}
			response, err := ctx.Send(request)
			if err != nil {
				return findings, err
			}
			marker := callback.ResponseMarker(token)
			pending = append(pending, callbackProbe{
				token: token, point: point, rule: payload.Name, request: request,
				response: response, marker: marker, inBand: strings.Contains(response.Text(), marker),
			})
			done++
			ctx.Progress(meta.ID, done, total)
			// A response that merely echoes the callback URL is not SSRF evidence.
			// Only an independent one-time callback can confirm this plugin.
		}
	}
	tokens := make([]string, 0, len(pending))
	for _, probe := range pending {
		if !probe.inBand {
			tokens = append(tokens, probe.token)
		}
	}
	hits := waitCallbackBatch(ctx.Context, ctx.Callbacks, tokens, 8*time.Second)
	for _, probe := range pending {
		if !probe.inBand && !hits[probe.token] {
			continue
		}
		title := "服务端产生唯一 SSRF 回连"
		summary := "收到唯一 SSRF 回连"
		metrics := map[string]any{"callback": true, "callback_token": probe.token, "payload_rule": probe.rule, "evidence_strength": "L5"}
		if probe.inBand {
			title = "服务端读取并回显 SSRF 回连内容"
			summary = "响应中出现回连服务专属标记"
			metrics["callback_response_marker"] = probe.marker
			metrics["in_band_callback"] = true
		}
		findings = append(findings, Finding(meta, title, model.SeverityCritical, model.ConfidenceCertain, probe.point.Label(),
			"扫描器收到由服务端触发的唯一回连 token，证明输入 URL 被服务端访问。",
			"对协议、域名和解析后的 IP 使用白名单；阻止私网、环回、链路本地地址及重定向绕过。",
			[]model.Evidence{ctx.Evidence(summary, probe.request, &probe.response, metrics)}, "OWASP WSTG-INPV-19"))
	}
	return findings, nil
}
