package plugin

import (
	"net/http"
	"net/url"
	"strings"

	"jungle_happy_Scan/internal/diff"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

type PathNormalization struct{}

func (PathNormalization) Meta() model.PluginMeta {
	return StandardMeta("path_normalization", "URL 路径归一化权限绕过", "比较正常匿名路径与重复斜杠、点段、矩阵参数、尾斜杠等变体，确认网关拒绝而 Spring 后端接受。", "state-changing", true)
}

func (p PathNormalization) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	anonymous, removed := httpraw.RemoveSessions(ctx.Request, ctx.Config.SessionIdentifiers)
	variants := normalizedPathVariants(anonymous)
	total := 1 + len(variants)*2
	ctx.Progress(meta.ID, 0, max(total, 1))
	if len(removed) == 0 || len(variants) == 0 {
		ctx.Progress(meta.ID, total, max(total, 1))
		return nil, nil
	}
	denied, err := ctx.Send(anonymous)
	if err != nil {
		return nil, err
	}
	done := 1
	if !methodDenied(denied, ctx) {
		ctx.Progress(meta.ID, total, max(total, 1))
		return nil, nil
	}
	for _, variant := range variants {
		first, sendErr := ctx.Send(variant.request)
		if sendErr != nil {
			return nil, sendErr
		}
		done++
		if !pathBypassAccepted(ctx, first) {
			done++
			continue
		}
		second, sendErr := ctx.Send(variant.request)
		if sendErr != nil {
			return nil, sendErr
		}
		done++
		ctx.Progress(meta.ID, min(done, total), total)
		if !pathBypassAccepted(ctx, second) || diff.Similarity(first, second, ctx.Config) < 0.90 {
			continue
		}
		ctx.Progress(meta.ID, total, max(total, 1))
		return []model.Finding{Finding(meta, "路径归一化差异绕过匿名访问控制", model.SeverityHigh, model.ConfidenceCertain, "path:"+variant.name,
			"移除全部会话后，规范路径被拒绝；同一资源的路径变体却两次返回与授权基线相近的成功内容，说明网关与 Spring/Servlet 对路径的解析结果不一致。",
			"在最外层网关完成一次严格规范化后再做鉴权，并将规范化后的路径传递给应用；拒绝重复斜杠、点段、分号矩阵参数及异常编码，确保 Spring Security 与代理采用一致规则。",
			[]model.Evidence{
				ctx.Evidence("规范路径匿名请求被拒绝", anonymous, &denied, map[string]any{"removed_sessions": removed}),
				ctx.Evidence("第一次匿名路径变体被接受", variant.request, &first, map[string]any{"variant": variant.name, "baseline_similarity": diff.Similarity(ctx.Baseline, first, ctx.Config)}),
				ctx.Evidence("第二次重复确认", variant.request, &second, map[string]any{"repeat_similarity": diff.Similarity(first, second, ctx.Config)}),
			}, "CWE-177", "Spring Security HttpFirewall")}, nil
	}
	ctx.Progress(meta.ID, max(done, total), max(total, 1))
	return nil, nil
}

type pathVariant struct {
	name    string
	request *httpraw.Request
}

func normalizedPathVariants(request *httpraw.Request) []pathVariant {
	parsed, err := url.Parse(request.Target)
	if err != nil {
		return nil
	}
	path := parsed.EscapedPath()
	if path == "" || path == "/" {
		return nil
	}
	add := func(name, changed string, out *[]pathVariant) {
		copyURL := *parsed
		copyURL.RawPath = changed
		copyURL.Path, _ = url.PathUnescape(changed)
		mutated := request.Clone()
		mutated.Target = copyURL.String()
		if mutated.Target != request.Target {
			*out = append(*out, pathVariant{name: name, request: mutated})
		}
	}
	var result []pathVariant
	if strings.Contains(path, "/") {
		add("duplicate-slash", strings.Replace(path, "/", "//", 1), &result)
	}
	trimmed := strings.TrimPrefix(path, "/")
	add("dot-segment", "/./"+trimmed, &result)
	segments := strings.Split(path, "/")
	for index := len(segments) - 1; index >= 0; index-- {
		if segments[index] != "" {
			copySegments := append([]string(nil), segments...)
			copySegments[index] += ";jhs=1"
			add("matrix-parameter", strings.Join(copySegments, "/"), &result)
			break
		}
	}
	if strings.HasSuffix(path, "/") {
		add("without-trailing-slash", strings.TrimSuffix(path, "/"), &result)
	} else {
		add("trailing-slash", path+"/", &result)
	}
	return result
}

func pathBypassAccepted(ctx *Context, response model.Response) bool {
	return response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices &&
		!diff.LikelyAuthDenied(response, ctx.Config) &&
		diff.Similarity(ctx.Baseline, response, ctx.Config) >= 0.82
}
