package plugin

import (
	"net/http"
	"regexp"
	"strings"

	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/diff"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

type MethodOverride struct{}

func (MethodOverride) Meta() model.PluginMeta {
	return StandardMeta("method_override", "HTTP Method Override 权限绕过", "覆盖 Spring _method、常见代理 Header，并用直接方法拒绝、原始基线差异和重复响应三重确认。", "state-changing", true)
}

type methodOverrideVariant struct {
	rule     config.PayloadRule
	request  *httpraw.Request
	affected string
}

func (p MethodOverride) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	variants := buildMethodOverrideVariants(ctx)
	total := len(variants) * 3
	ctx.Progress(meta.ID, 0, max(total, 1))
	done := 0
	var findings []model.Finding
	for _, variant := range variants {
		method := strings.ToUpper(strings.TrimSpace(variant.rule.Payload))
		direct := ctx.Request.Clone()
		direct.Method = method
		directResponse, err := ctx.Send(direct)
		if err != nil {
			return findings, err
		}
		done++
		if !methodDenied(directResponse, ctx) {
			done += 2
			ctx.Progress(meta.ID, min(done, total), max(total, 1))
			continue
		}

		first, err := ctx.Send(variant.request)
		if err != nil {
			return findings, err
		}
		done++
		if !methodAccepted(first, ctx) || !overrideSemanticallyChanged(ctx, first, variant.rule.Expected) {
			done++
			ctx.Progress(meta.ID, min(done, total), max(total, 1))
			continue
		}
		second, err := ctx.Send(variant.request)
		if err != nil {
			return findings, err
		}
		done++
		ctx.Progress(meta.ID, min(done, total), max(total, 1))
		if !methodAccepted(second, ctx) || !overrideSemanticallyChanged(ctx, second, variant.rule.Expected) ||
			diff.Similarity(first, second, ctx.Config) < 0.90 {
			continue
		}
		findings = append(findings, Finding(meta, "Method Override 绕过方法限制", model.SeverityHigh, model.ConfidenceCertain, variant.affected,
			"直接使用 "+method+" 被网关或权限层拒绝；覆盖请求两次均成功且与原始方法响应存在稳定语义差异，排除了覆盖字段被忽略造成的误报。",
			"网关、Servlet Filter 和业务授权必须使用同一个最终 HTTP Method；不需要时禁用 HiddenHttpMethodFilter 与 Method Override Header，需要时仅允许明确的来源和方法白名单。",
			[]model.Evidence{
				ctx.Evidence("原始方法基线", ctx.Request, &ctx.Baseline, map[string]any{"baseline_stability": diff.BaselineStability(ctx.Baselines, ctx.Config)}),
				ctx.Evidence("直接 "+method+" 请求被拒绝", direct, &directResponse, nil),
				ctx.Evidence("第一次覆盖请求被后端按目标方法处理", variant.request, &first, map[string]any{"payload_rule": variant.rule.Name, "method": method, "baseline_similarity": diff.Similarity(ctx.Baseline, first, ctx.Config)}),
				ctx.Evidence("第二次反复确认", variant.request, &second, map[string]any{"repeat_similarity": diff.Similarity(first, second, ctx.Config)}),
			}, "CWE-650", "Spring HiddenHttpMethodFilter"))
		break
	}
	ctx.Progress(meta.ID, max(done, total), max(total, 1))
	return findings, nil
}

func buildMethodOverrideVariants(ctx *Context) []methodOverrideVariant {
	var result []methodOverrideVariant
	for _, rule := range payloadsForMode(ctx.Rule("method_override"), ctx.Mode) {
		method := strings.ToUpper(strings.TrimSpace(rule.Payload))
		if method != http.MethodPut && method != http.MethodPatch && method != http.MethodDelete {
			continue
		}
		kind := strings.ToLower(strings.TrimSpace(rule.Kind))
		switch kind {
		case "query_param":
			request, err := httpraw.AddParameter(ctx.Request, "query", defaultString(rule.Group, "_method"), method)
			if err == nil {
				result = append(result, methodOverrideVariant{rule: rule, request: request, affected: "query:" + defaultString(rule.Group, "_method")})
			}
		case "form_param":
			request, err := httpraw.AddParameter(ctx.Request, "form", defaultString(rule.Group, "_method"), method)
			if err == nil {
				result = append(result, methodOverrideVariant{rule: rule, request: request, affected: "form:" + defaultString(rule.Group, "_method")})
			}
		case "multipart_param":
			request, err := httpraw.AddParameter(ctx.Request, "multipart", defaultString(rule.Group, "_method"), method)
			if err == nil {
				result = append(result, methodOverrideVariant{rule: rule, request: request, affected: "multipart:" + defaultString(rule.Group, "_method")})
			}
		default:
			if strings.TrimSpace(rule.Header) != "" {
				result = append(result, methodOverrideVariant{rule: rule, request: ctx.Request.WithHeader(rule.Header, method), affected: "header:" + rule.Header})
			}
		}
	}
	return result
}

func overrideSemanticallyChanged(ctx *Context, response model.Response, expected string) bool {
	if expected != "" {
		if pattern, err := regexp.Compile(expected); err == nil && pattern.Match(response.Body) && !pattern.Match(ctx.Baseline.Body) {
			return true
		}
	}
	if response.StatusCode != ctx.Baseline.StatusCode {
		return true
	}
	return diff.BaselineStability(ctx.Baselines, ctx.Config) >= 0.80 &&
		diff.Similarity(ctx.Baseline, response, ctx.Config) <= 0.80
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func methodDenied(response model.Response, ctx *Context) bool {
	return response.StatusCode == http.StatusMethodNotAllowed || response.StatusCode == http.StatusUnauthorized ||
		response.StatusCode == http.StatusForbidden || diff.LikelyAuthDenied(response, ctx.Config)
}

func methodAccepted(response model.Response, ctx *Context) bool {
	return response.StatusCode >= 200 && response.StatusCode < 300 && !diff.LikelyAuthDenied(response, ctx.Config)
}
