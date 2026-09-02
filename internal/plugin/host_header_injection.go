package plugin

import (
	"regexp"
	"strings"

	"jungle_happy_Scan/internal/model"
)

type HostHeaderInjection struct{}

func (HostHeaderInjection) Meta() model.PluginMeta {
	return StandardMeta("host_header_injection", "Host Header 信任注入", "测试 Spring/代理是否信任 X-Forwarded-Host 等头并生成受污染的绝对跳转或页面链接。", "active", true)
}

func (p HostHeaderInjection) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	payloads := payloadsForMode(ctx.Rule(meta.ID), ctx.Mode)
	total := len(payloads) * 2
	done := 0
	ctx.Progress(meta.ID, 0, max(total, 1))
	for _, payload := range payloads {
		canary := strings.ToLower(randomID("jhs")) + ".invalid"
		value := expandPayload(payload.Payload, map[string]string{"host": canary})
		request := ctx.Request.WithHeader(payload.Header, value)
		first, err := ctx.Send(request)
		if err != nil {
			return nil, err
		}
		done++
		ctx.Progress(meta.ID, done, total)
		if !absoluteHostEvidence(first, canary) || absoluteHostEvidence(ctx.Baseline, canary) {
			done++
			ctx.Progress(meta.ID, done, total)
			continue
		}
		second, err := ctx.Send(request)
		if err != nil {
			return nil, err
		}
		done++
		ctx.Progress(meta.ID, done, total)
		if !absoluteHostEvidence(second, canary) {
			continue
		}
		return []model.Finding{Finding(meta, "代理 Host Header 可污染绝对 URL", model.SeverityHigh, model.ConfidenceCertain, "header:"+payload.Header,
			"两次响应的 Location 或 HTML 绝对链接均包含唯一外部主机名，说明应用/代理信任了客户端提供的 Host 转发头。",
			"在可信反向代理处覆盖并清理转发头；应用配置允许主机列表；生成重置密码等安全链接时使用固定外部基址。",
			[]model.Evidence{
				ctx.Evidence("首次响应生成受污染绝对 URL", request, &first, map[string]any{"match": canary}),
				ctx.Evidence("第二次重复确认", request, &second, map[string]any{"match": canary, "repeat_confirmed": true}),
			}, "CWE-644")}, nil
	}
	return nil, nil
}

func absoluteHostEvidence(response model.Response, host string) bool {
	location := strings.ToLower(response.Header("Location"))
	if strings.Contains(location, "://"+host) || strings.HasPrefix(location, "//"+host) {
		return true
	}
	quoted := regexp.QuoteMeta(host)
	pattern := regexp.MustCompile(`(?is)(?:href|action|src)\s*=\s*["'](?:https?:)?//` + quoted + `(?:[/:"'])`)
	return pattern.Match(response.Body)
}
