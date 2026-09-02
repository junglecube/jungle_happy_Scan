package plugin

import (
	"net/http"
	"strings"

	"jungle_happy_Scan/internal/diff"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

type CSRF struct{}

func (CSRF) Meta() model.PluginMeta {
	return StandardMeta("csrf", "CSRF 防护缺失", "验证 Cookie 会话状态变更请求在跨站 Origin 且无 CSRF Header 时是否仍被接受。", "state-changing", true)
}

func (p CSRF) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	if !stateChangingMethod(ctx.Request.Method) || ctx.Request.Header("Cookie") == "" {
		ctx.Progress(meta.ID, 1, 1)
		return nil, nil
	}
	request := ctx.Request.Clone()
	payloads := payloadsForMode(ctx.Rule(meta.ID), ctx.Mode)
	origin := ""
	for _, payload := range payloads {
		if payload.Kind == "origin" {
			origin = payload.Payload
			break
		}
	}
	if origin == "" {
		ctx.Progress(meta.ID, 1, 1)
		return nil, nil
	}
	removed := make([]string, 0)
	for _, name := range ctx.Config.CSRFHeaderNames {
		if request.Header(name) != "" {
			removed = append(removed, name)
			request = request.WithoutHeaders(name)
		}
	}
	// CSRF tokens are frequently carried as Spring form/query fields rather
	// than headers. Empty every recognized occurrence while preserving cookies,
	// because a real cross-site browser request would still carry session and
	// double-submit cookies according to their SameSite policy.
	csrfNames := append([]string(nil), ctx.Config.CSRFHeaderNames...)
	csrfNames = append(csrfNames, "_csrf", "csrf", "csrfToken", "csrf_token", "xsrfToken", "xsrf_token")
	for _, point := range httpraw.Discover(request, false) {
		if !exactSemanticName(point.Name, csrfNames) || point.Location == "cookie" {
			continue
		}
		freshPoint, found := freshInsertionPoint(request, point)
		if !found {
			continue
		}
		if mutated, mutateErr := httpraw.Mutate(request, freshPoint, ""); mutateErr == nil {
			request = mutated
			removed = append(removed, point.Label())
		}
	}
	request = request.WithHeader("Origin", origin)
	request = request.WithHeader("Referer", strings.TrimRight(origin, "/")+"/csrf-test")
	ctx.Progress(meta.ID, 0, 1)
	response, err := ctx.Send(request)
	if err != nil {
		return nil, err
	}
	ctx.Progress(meta.ID, 1, 1)
	similarity := diff.Similarity(ctx.Baseline, response, ctx.Config)
	if !diff.LikelySuccess(response, ctx.Config) || diff.LikelyAuthDenied(response, ctx.Config) || similarity < 0.85 {
		return nil, nil
	}
	confidence := model.ConfidenceFirm
	severity := model.SeverityMedium
	if len(removed) == 0 {
		confidence = model.ConfidenceTentative
		severity = model.SeverityLow
	}
	return []model.Finding{Finding(meta, "跨站状态变更请求仍被接受", severity, confidence, "request",
		"请求使用 Cookie 会话；替换为跨站 Origin/Referer 并移除常见 CSRF Header 后，服务端仍返回与基线相似的成功响应。SameSite Cookie 等浏览器侧控制仍需人工复核。",
		"使用 SameSite Cookie，并在服务端校验与会话绑定的不可预测 CSRF token，同时验证 Origin/Referer。",
		[]model.Evidence{ctx.Evidence("跨站请求得到成功响应", request, &response, map[string]any{"similarity": similarity, "removed_headers": removed})},
		"OWASP WSTG-SESS-05")}, nil
}

func freshInsertionPoint(request *httpraw.Request, wanted httpraw.InsertionPoint) (httpraw.InsertionPoint, bool) {
	for _, candidate := range httpraw.Discover(request, false) {
		if candidate.Location == wanted.Location && candidate.Path == wanted.Path && candidate.Occurrence == wanted.Occurrence {
			return candidate, true
		}
	}
	return httpraw.InsertionPoint{}, false
}

func exactSemanticName(name string, candidates []string) bool {
	for _, candidate := range candidates {
		if strings.EqualFold(strings.TrimSpace(name), strings.TrimSpace(candidate)) {
			return true
		}
	}
	return false
}

func stateChangingMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}
