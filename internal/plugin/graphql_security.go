package plugin

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/diff"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

type GraphQLSecurity struct{}

func (GraphQLSecurity) Meta() model.PluginMeta {
	return StandardMeta("graphql_security", "GraphQL 安全配置", "检测 introspection、字段建议、批量请求和别名批处理限制缺失，不猜测业务字段。", "active", true)
}

func (p GraphQLSecurity) Scan(ctx *Context) ([]model.Finding, error) {
	return scanGraphQLSecurity(ctx, p.Meta())
}

func scanGraphQLSecurity(ctx *Context, meta model.PluginMeta) ([]model.Finding, error) {
	rule := ctx.Rule(meta.ID)
	paths := graphqlPaths(ctx.Request, rule.Paths)
	payloads := payloadsForMode(rule, ctx.Mode)
	total := len(paths) * len(payloads) * 2
	done := 0
	ctx.Progress(meta.ID, 0, max(total, 1))
	var findings []model.Finding
	for _, targetPath := range paths {
		for _, payload := range payloads {
			expected, err := regexp.Compile(payload.Expected)
			if err != nil || (payload.Expected == "" && payload.Kind != "batch" && payload.Kind != "alias_batch") {
				done += 2
				continue
			}
			request := graphqlRequest(ctx.Request, targetPath, payload)
			if payload.Kind == "batch" {
				request = graphqlBatchRequest(ctx.Request, targetPath, 20)
			}
			if payload.Kind == "alias_batch" {
				request = graphqlAliasRequest(ctx.Request, targetPath, 32)
			}
			first, err := ctx.Send(request)
			if err != nil {
				return findings, err
			}
			done++
			if first.StatusCode != 200 || !graphqlExpected(payload.Kind, expected, first.Body) || diff.LikelyAuthDenied(first, ctx.Config) {
				done++
				continue
			}
			second, err := ctx.Send(request)
			if err != nil {
				return findings, err
			}
			done++
			ctx.Progress(meta.ID, done, total)
			if second.StatusCode != 200 || !graphqlExpected(payload.Kind, expected, second.Body) {
				continue
			}
			severityValue := model.SeverityLow
			if payload.Kind == "batch" || payload.Kind == "alias_batch" {
				severityValue = model.SeverityMedium
			}
			findings = append(findings, Finding(meta, graphqlFindingTitle(payload.Kind), severityValue, model.ConfidenceCertain, targetPath,
				"同一 GraphQL 探测两次返回明确特征；批量类检查仅在一次接受 20 个 JSON 操作或 32 个别名时报告。",
				"生产环境按需关闭 introspection 和字段建议；限制单请求操作数、别名数、查询深度与复杂度；每个 resolver 独立鉴权。",
				[]model.Evidence{
					ctx.Evidence("第一次 GraphQL 配置探测成功", request, &first, map[string]any{"payload_rule": payload.Name, "kind": payload.Kind}),
					ctx.Evidence("第二次重复确认", request, &second, nil),
				}, "OWASP WSTG-APIT-01"))
		}
	}
	ctx.Progress(meta.ID, max(done, total), max(total, 1))
	return findings, nil
}

func graphqlBatchRequest(original *httpraw.Request, path string, count int) *httpraw.Request {
	operations := make([]map[string]string, count)
	for index := range operations {
		operations[index] = map[string]string{"query": "{__typename}"}
	}
	body, _ := json.Marshal(operations)
	request := original.ReplaceTarget(path)
	request.Method = "POST"
	request = request.WithHeader("Content-Type", "application/json")
	return request.WithBody(body)
}

func graphqlAliasRequest(original *httpraw.Request, path string, count int) *httpraw.Request {
	var query strings.Builder
	query.WriteByte('{')
	for index := 1; index <= count; index++ {
		query.WriteString("jhs")
		query.WriteString(strconv.Itoa(index))
		query.WriteString(":__typename ")
	}
	query.WriteByte('}')
	body, _ := json.Marshal(map[string]string{"query": query.String()})
	request := original.ReplaceTarget(path)
	request.Method = "POST"
	request = request.WithHeader("Content-Type", "application/json")
	return request.WithBody(body)
}

func graphqlExpected(kind string, expected *regexp.Regexp, body []byte) bool {
	switch kind {
	case "batch":
		var responses []any
		return json.Unmarshal(body, &responses) == nil && len(responses) >= 20
	case "alias_batch":
		return strings.Contains(string(body), `"jhs1"`) && strings.Contains(string(body), `"jhs32"`)
	default:
		return expected != nil && expected.Match(body)
	}
}

func graphqlPaths(request *httpraw.Request, configured []string) []string {
	seen := map[string]bool{}
	var result []string
	if strings.Contains(strings.ToLower(request.Target), "graphql") {
		result = append(result, request.Target)
		seen[request.Target] = true
	}
	for _, path := range configured {
		if path != "" && !seen[path] {
			result = append(result, path)
			seen[path] = true
		}
	}
	return result
}

func graphqlRequest(original *httpraw.Request, path string, payload config.PayloadRule) *httpraw.Request {
	request := original.ReplaceTarget(path)
	request.Method = "POST"
	request = request.WithHeader("Content-Type", "application/json")
	if payload.Kind == "batch" {
		request = request.WithBody([]byte(payload.Payload))
	} else {
		body, _ := json.Marshal(map[string]string{"query": payload.Payload})
		request = request.WithBody(body)
	}
	return request
}

func graphqlFindingTitle(kind string) string {
	switch kind {
	case "introspection":
		return "GraphQL Introspection 可访问"
	case "suggestion":
		return "GraphQL 字段建议泄露"
	case "batch":
		return "GraphQL 接受批量请求"
	case "alias_batch":
		return "GraphQL 别名批处理缺少限制"
	default:
		return "GraphQL 安全限制缺失"
	}
}
