package plugin

import (
	"jungle_happy_Scan/internal/diff"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

type Unauthorized struct{}

func (Unauthorized) Meta() model.PluginMeta {
	return StandardMeta("unauthorized", "未授权访问", "移除全部配置及自动识别的会话标识；无鉴权字段时按接口必须登录配置判断。", "active", true)
}

func (p Unauthorized) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	if diff.LikelyAuthDenied(ctx.Baseline, ctx.Config) {
		ctx.Progress(meta.ID, 1, 1)
		return nil, nil
	}
	identifiers := httpraw.EffectiveSessionIdentifiers(ctx.Request, ctx.Config.SessionIdentifiers)
	anonymous, removed := httpraw.RemoveSessions(ctx.Request, identifiers)
	if len(removed) == 0 {
		ctx.Progress(meta.ID, 1, 1)
		if !ctx.Config.AuthorizationExpected {
			return nil, nil
		}
		return []model.Finding{Finding(meta, "接口未携带鉴权凭据仍可访问", model.SeverityMedium, model.ConfidenceFirm, "request",
			"原始报文未发现配置或自动识别的会话凭据，但接口直接返回非鉴权失败的业务响应；当前配置声明该接口应当要求登录。",
			"在服务端统一实施认证与权限校验；对必须登录的接口拒绝所有未携带有效身份的请求。",
			[]model.Evidence{ctx.Evidence("无鉴权字段的原始请求直接返回业务响应", ctx.Request, &ctx.Baseline, map[string]any{"authorization_expected": true})},
			"OWASP WSTG-ATHZ-02")}, nil
	}
	invalid, changed := httpraw.InvalidateSessions(ctx.Request, identifiers, "invalid-scanner-session")
	for _, payload := range payloadsForMode(ctx.Rule(meta.ID), ctx.Mode) {
		if payload.Kind == "invalid_session" {
			invalid, changed = httpraw.InvalidateSessions(ctx.Request, identifiers, payload.Payload)
			break
		}
	}
	ctx.Progress(meta.ID, 0, 2)
	noSession, err := ctx.Send(anonymous)
	if err != nil {
		return nil, err
	}
	ctx.Progress(meta.ID, 1, 2)
	badSession, err := ctx.Send(invalid)
	if err != nil {
		return nil, err
	}
	ctx.Progress(meta.ID, 2, 2)
	noSimilarity := diff.Similarity(ctx.Baseline, noSession, ctx.Config)
	badSimilarity := diff.Similarity(ctx.Baseline, badSession, ctx.Config)
	if diff.LikelyAuthDenied(noSession, ctx.Config) || diff.LikelyAuthDenied(badSession, ctx.Config) {
		return nil, nil
	}
	if noSimilarity < 0.90 || badSimilarity < 0.85 {
		return nil, nil
	}
	confidence := model.ConfidenceFirm
	severity := model.SeverityMedium
	if ctx.Config.AuthorizationExpected {
		if noSimilarity >= 0.97 && badSimilarity >= 0.95 {
			confidence = model.ConfidenceCertain
		}
	} else {
		confidence = model.ConfidenceTentative
	}
	description := "移除全部已配置会话标识后，接口仍返回与授权基线高度相似的业务响应。"
	if !ctx.Config.AuthorizationExpected {
		description += " 当前未配置“接口预期必须登录”，公共接口也可能出现该现象。"
	}
	return []model.Finding{Finding(meta, "接口无需有效会话即可访问", severity, confidence, "session", description,
		"在服务端统一实施认证与权限校验；不要依赖前端页面、隐藏按钮或单一网关规则。",
		[]model.Evidence{
			ctx.Evidence("删除会话后响应仍与授权基线相似", anonymous, &noSession, map[string]any{"similarity": noSimilarity, "removed": removed}),
			ctx.Evidence("替换为无效会话后响应仍然相似", invalid, &badSession, map[string]any{"similarity": badSimilarity, "changed": changed}),
		}, "OWASP WSTG-ATHZ-02")}, nil
}
