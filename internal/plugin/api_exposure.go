package plugin

import (
	"net/http"
	"net/url"
	"path"
	"strings"

	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

type APIExposure struct{}

func (APIExposure) Meta() model.PluginMeta {
	return StandardMeta("api_exposure", "OpenAPI 暴露", "探测 Java 系统常见的同源 OpenAPI、Swagger UI、Knife4j 接口描述路径，不再包含 GraphQL。", "adjacent-path", true)
}

func (p APIExposure) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	paths := contextualPaths(ctx.Request, ctx.Rule(meta.ID).Paths)
	ctx.Progress(meta.ID, 0, max(len(paths), 1))
	var findings []model.Finding
	for index, targetPath := range paths {
		request := ctx.Request.ReplaceTarget(targetPath)
		request.Method = http.MethodGet
		request = request.WithBody(nil).WithoutHeaders("Content-Type", "Content-Length")
		request, _ = httpraw.RemoveSessions(request, httpraw.EffectiveSessionIdentifiers(request, ctx.Config.SessionIdentifiers))
		response, err := ctx.Send(request)
		if err != nil {
			return findings, err
		}
		ctx.Progress(meta.ID, index+1, len(paths))
		text := strings.ToLower(response.Text())
		if response.StatusCode != http.StatusOK {
			continue
		}
		switch {
		case strings.Contains(text, `"openapi"`) && (strings.Contains(text, `"paths"`) || strings.Contains(text, `"components"`)):
			findings = append(findings, exposureFinding(ctx, meta, request, response, targetPath, "OpenAPI 接口定义可匿名访问", "响应包含 OpenAPI 定义和接口路径结构。"))
		case strings.Contains(text, `"swagger"`) && strings.Contains(text, `"paths"`) && (strings.Contains(text, `"definitions"`) || strings.Contains(text, `"info"`)):
			findings = append(findings, exposureFinding(ctx, meta, request, response, targetPath, "Swagger 2 接口定义可匿名访问", "响应包含 Swagger 2.0 接口定义结构。"))
		case strings.Contains(text, "swagger ui") || strings.Contains(text, "swagger-ui"):
			findings = append(findings, exposureFinding(ctx, meta, request, response, targetPath, "Swagger UI 可匿名访问", "响应包含 Swagger UI 页面特征。"))
		case strings.Contains(text, "knife4j") || strings.Contains(text, "doc.html") && strings.Contains(text, "swagger"):
			findings = append(findings, exposureFinding(ctx, meta, request, response, targetPath, "Knife4j 接口文档可匿名访问", "响应包含 Knife4j/Swagger 接口文档页面特征。"))
		}
	}
	return findings, nil
}

// contextualPaths tests both server-root and likely servlet context roots.
// A pasted /ctp/mobile/order request may expose documentation at
// /ctp/v3/api-docs even when /v3/api-docs is absent.
func contextualPaths(request *httpraw.Request, configured []string) []string {
	prefixes := []string{""}
	if parsed, err := url.Parse(request.Target); err == nil {
		segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
		prefix := ""
		for index, segment := range segments {
			if segment == "" || index >= 3 || index == len(segments)-1 {
				break
			}
			prefix += "/" + segment
			prefixes = append(prefixes, prefix)
		}
	}
	seen := make(map[string]bool)
	result := make([]string, 0, len(configured)*len(prefixes))
	for _, prefix := range prefixes {
		for _, configuredPath := range configured {
			candidate := path.Clean("/" + strings.Trim(prefix, "/") + "/" + strings.Trim(configuredPath, "/"))
			if candidate != "." && !seen[candidate] {
				seen[candidate] = true
				result = append(result, candidate)
			}
		}
	}
	return result
}

func exposureFinding(ctx *Context, meta model.PluginMeta, request *httpraw.Request, response model.Response, targetPath, title, description string) model.Finding {
	return Finding(meta, title, model.SeverityLow, model.ConfidenceCertain, targetPath, description+" 测试环境中可能是预期行为。",
		"生产环境关闭或保护 OpenAPI/Swagger/Knife4j 接口文档；确保描述文件不包含密钥、内部地址及敏感模型。",
		[]model.Evidence{ctx.Evidence("匿名响应包含明确接口描述特征", request, &response, map[string]any{"path": targetPath})})
}
