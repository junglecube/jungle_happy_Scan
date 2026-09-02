package plugin

import (
	"net/http"
	"sort"
	"strings"

	"jungle_happy_Scan/internal/model"
)

type SecurityHeaders struct{}

func (SecurityHeaders) Meta() model.PluginMeta {
	return PassiveMeta("security_headers", "安全响应头", "被动检查 HTML 响应的 CSP、点击劫持和 MIME 嗅探防护。")
}

func (p SecurityHeaders) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	ctx.Progress(meta.ID, 1, 1)
	htmlResponse := xssHTMLResponse(strings.ToLower(ctx.Baseline.Header("Content-Type")), ctx.Baseline.Text())
	var missing []string
	if htmlResponse {
		contentType := strings.ToLower(strings.TrimSpace(ctx.Baseline.Header("Content-Type")))
		if contentType == "" || strings.Contains(contentType, "application/octet-stream") ||
			strings.Contains(contentType, "binary/octet-stream") || strings.Contains(contentType, "unknown/unknown") {
			missing = append(missing, "Content-Type（缺失或歧义，存在 MIME 嗅探风险）")
		}
		csp := strings.TrimSpace(ctx.Baseline.Header("Content-Security-Policy"))
		if csp == "" {
			missing = append(missing, "Content-Security-Policy")
		}
		xFrameOptions := strings.ToUpper(strings.TrimSpace(ctx.Baseline.Header("X-Frame-Options")))
		validFrameOptions := xFrameOptions == "DENY" || xFrameOptions == "SAMEORIGIN"
		if !validFrameOptions && !strings.Contains(strings.ToLower(csp), "frame-ancestors") {
			missing = append(missing, "X-Frame-Options/frame-ancestors")
		}
		if !strings.EqualFold(strings.TrimSpace(ctx.Baseline.Header("X-Content-Type-Options")), "nosniff") {
			missing = append(missing, "X-Content-Type-Options: nosniff")
		}
		if strings.EqualFold(ctx.Request.Scheme, "https") && strings.TrimSpace(ctx.Baseline.Header("Strict-Transport-Security")) == "" {
			missing = append(missing, "Strict-Transport-Security")
		}
	}
	var findings []model.Finding
	if len(missing) > 0 {
		findings = append(findings, Finding(meta, "HTML 响应缺少或使用无效安全响应头", model.SeverityLow, model.ConfidenceCertain, "response headers",
			"缺少或无效："+strings.Join(missing, "、"), "部署严格 CSP、frame-ancestors 和 nosniff；HTTPS 页面同时配置 HSTS。",
			[]model.Evidence{ctx.Evidence("缺少或无效的浏览器安全响应头", nil, &ctx.Baseline, map[string]any{"missing_or_invalid": missing})}))
	}
	if issues := insecureSessionCookieAttributes(ctx); len(issues) > 0 {
		findings = append(findings, Finding(meta, "会话 Cookie 缺少安全属性", model.SeverityMedium, model.ConfidenceCertain, "response headers:Set-Cookie",
			"会话 Cookie 属性问题："+strings.Join(issues, "；"),
			"会话 Cookie 配置 HttpOnly、SameSite；HTTPS 环境必须配置 Secure，SameSite=None 必须与 Secure 同时使用。",
			[]model.Evidence{ctx.Evidence("逐条解析 Set-Cookie 后发现会话 Cookie 属性缺失", nil, &ctx.Baseline, map[string]any{"issues": issues})}))
	}
	return findings, nil
}

func insecureSessionCookieAttributes(ctx *Context) []string {
	var issues []string
	for _, raw := range ctx.Baseline.HeaderAll("Set-Cookie") {
		cookie, err := http.ParseSetCookie(raw)
		if err != nil || !sessionCookieName(cookie.Name, ctx.Config.SessionIdentifiers) {
			continue
		}
		if !cookie.HttpOnly {
			issues = append(issues, cookie.Name+" 缺少 HttpOnly")
		}
		if strings.EqualFold(ctx.Request.Scheme, "https") && !cookie.Secure {
			issues = append(issues, cookie.Name+" 缺少 Secure")
		}
		if cookie.SameSite == http.SameSiteDefaultMode {
			issues = append(issues, cookie.Name+" 缺少 SameSite")
		}
		if cookie.SameSite == http.SameSiteNoneMode && !cookie.Secure {
			issues = append(issues, cookie.Name+" SameSite=None 但缺少 Secure")
		}
	}
	sort.Strings(issues)
	return issues
}

func sessionCookieName(name string, configured []string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return false
	}
	for _, marker := range []string{"jsessionid", "sessionid", "session", "dessession", "dsesession", "sid", "token", "auth"} {
		if lower == marker || strings.Contains(lower, marker) {
			return true
		}
	}
	for _, marker := range configured {
		marker = strings.ToLower(strings.TrimSpace(marker))
		if marker != "" && marker != "cookie" && lower == marker {
			return true
		}
	}
	return false
}
