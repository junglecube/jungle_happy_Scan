package plugin

import (
	"strings"

	"jungle_happy_Scan/internal/callback"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

type SSRF struct{}

func (SSRF) Meta() model.PluginMeta {
	return StandardMeta("ssrf", "SSRF", "向配置的 URL 类参数注入回连 payload，支持同步响应与离线回连确认。", "active", true)
}

func (p SSRF) Scan(ctx *Context) (findings []model.Finding, scanErr error) {
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
	defer func() {
		byToken := map[string]callbackProbe{}
		var tokens []string
		build := func(token string, late bool) model.Finding {
			probe := byToken[token]
			metrics := map[string]any{"callback": true, "callback_token": token, "payload_rule": probe.rule, "evidence_strength": "L5", "late_callback": late}
			if probe.inBand {
				metrics["callback_response_marker"] = probe.marker
				metrics["in_band_callback"] = true
			}
			title := "服务端访问了输入的外部 URL"
			if probe.inBand {
				title = "服务端读取并回显 SSRF 回连内容"
			}
			return Finding(p.Meta(), title, model.SeverityMedium, model.ConfidenceCertain, probe.point.Label(),
				"唯一回连或专属响应内容证明服务端访问了输入 URL；未证明私网访问、权限绕过或敏感数据读取，合法 webhook 需结合业务范围复核。",
				"明确允许访问的目标范围，并验证解析地址和重定向目标。", []model.Evidence{ctx.Evidence("外部 URL 访问证据", probe.request, &probe.response, metrics)}, "OWASP WSTG-INPV-19")
		}
		for _, probe := range pending {
			byToken[probe.token] = probe
			if probe.inBand {
				findings = append(findings, build(probe.token, false))
			} else {
				tokens = append(tokens, probe.token)
			}
		}
		findings = append(findings, settleOAST(ctx, tokens, build)...)
	}()

	for _, point := range points {
		for _, payload := range payloads {
			token, callbackURL := ctx.Callbacks.Register(ctx.Config.CallbackBaseURL, "ssrf")
			value := expandPayload(payload.Payload, map[string]string{"callback": callbackURL, "token": token, "value": point.Value})
			request, err := ctx.Mutate(point, value)
			if err != nil {
				continue
			}
			response, err := ctx.Send(request)

			marker := callback.ResponseMarker(token)
			pending = append(pending, callbackProbe{
				token: token, point: point, rule: payload.Name, request: request,
				response: response, marker: marker, inBand: strings.Contains(response.Text(), marker),
			})
			if err != nil {
				return findings, err
			}
			done++
			ctx.Progress(meta.ID, done, total)
			// A response that merely echoes the callback URL is not SSRF evidence.
			// Only an independent one-time callback can confirm this plugin.
		}
	}
	return findings, nil
}
