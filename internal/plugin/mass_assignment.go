package plugin

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/diff"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

type MassAssignment struct{}

func (MassAssignment) Meta() model.PluginMeta {
	return StandardMeta("mass_assignment", "Mass Assignment 过度字段绑定", "覆盖 Spring/CTP 的 JSON 对象与数组、query、form、multipart 多来源绑定，并通过重复回显或同源读取确认。", "state-changing", true)
}

type bindingVariant struct {
	request  *httpraw.Request
	affected string
	source   string
}

func (p MassAssignment) Scan(ctx *Context) ([]model.Finding, error) {
	return scanMassAssignment(ctx, p.Meta(), false)
}

func scanMassAssignment(ctx *Context, meta model.PluginMeta, extended bool) ([]model.Finding, error) {
	payloads := payloadsForMode(ctx.Rule(meta.ID), ctx.Mode)
	// Each viable binding variant performs two acceptance requests and may add a
	// same-origin persistence read. Keep progress aligned with the real plan even
	// for deeply nested JSON arrays instead of using the historical fixed guess.
	total := 0
	for _, payload := range payloads {
		total += len(massAssignmentVariants(ctx.Request, payload, extended)) * 3
	}
	done := 0
	ctx.Progress(meta.ID, 0, max(total, 1))
	var findings []model.Finding
	for _, payload := range payloads {
		if payload.Group == "" || payload.Expected == "" {
			continue
		}
		expected, err := regexp.Compile(payload.Expected)
		if err != nil || expected.Match(ctx.Baseline.Body) {
			continue
		}
		variants := massAssignmentVariants(ctx.Request, payload, extended)
		if len(variants) == 0 {
			continue
		}
		for _, variant := range variants {
			first, err := ctx.Send(variant.request)
			if err != nil {
				return findings, err
			}
			done++
			if first.StatusCode < 200 || first.StatusCode >= 300 || !expected.Match(first.Body) || diff.LikelyAuthDenied(first, ctx.Config) {
				continue
			}
			second, err := ctx.Send(variant.request)
			if err != nil {
				return findings, err
			}
			done++
			if !expected.Match(second.Body) || diff.Similarity(first, second, ctx.Config) < 0.88 {
				continue
			}
			confidenceValue := model.ConfidenceTentative
			severityValue := model.SeverityLow
			description := "在 " + variant.source + " 中加入不应由客户端控制的字段后，两次响应均回显该值。这只证明 DTO/响应回显，在未二次读取前不把它判为已持久化越权。"
			evidence := []model.Evidence{
				ctx.Evidence("第一次响应接受敏感绑定字段", variant.request, &first, map[string]any{"field": payload.Group, "source": variant.source, "payload_rule": payload.Name}),
				ctx.Evidence("第二次重复确认", variant.request, &second, map[string]any{"field": payload.Group}),
			}
			resourcePath := uploadedResourcePath(first)
			if strings.HasPrefix(strings.TrimSpace(payload.Header), "/") {
				resourcePath = strings.TrimSpace(payload.Header)
			}
			if resourcePath != "" {
				verify := ctx.Request.ReplaceTarget(resourcePath)
				verifyResponse, verifyErr := ctx.Send(verify)
				if verifyErr == nil && verifyResponse.StatusCode >= 200 && verifyResponse.StatusCode < 300 && expected.Match(verifyResponse.Body) {
					confidenceValue = model.ConfidenceCertain
					severityValue = model.SeverityHigh
					description += " 随后通过响应给出的同源资源地址以 GET 读取，敏感字段仍然存在，已确认持久化。"
					evidence = append(evidence, ctx.Evidence("同源二次读取确认字段已持久化", verify, &verifyResponse, map[string]any{"resource_path": resourcePath}))
				}
			}
			findings = append(findings, Finding(meta, "服务端接受敏感绑定字段 "+payload.Group, severityValue, confidenceValue, variant.affected,
				description,
				"Spring/CTP 使用专用 DTO、构造器绑定和 allowedFields；禁止请求对象直接绑定持久化实体；角色、机构、归属、审批与启用状态必须由服务端赋值。",
				evidence, "CWE-915", "Spring MVC Data Binding"))
			break
		}
		ctx.Progress(meta.ID, min(done, total), max(total, 1))
	}
	ctx.Progress(meta.ID, total, max(total, 1))
	return findings, nil
}

func massAssignmentVariants(request *httpraw.Request, payload config.PayloadRule, extended bool) []bindingVariant {
	var result []bindingVariant
	ctype := request.ContentType()
	rawString := scalarPayload(payload.Payload)
	if strings.Contains(ctype, "json") {
		for _, path := range jsonBindingPaths(request.Body, payload.Group) {
			mutated, err := httpraw.AddJSONField(request, path, payload.Payload)
			if err == nil {
				result = append(result, bindingVariant{request: mutated, affected: "json:" + path, source: "JSON"})
			}
		}
		// Spring @ModelAttribute and CTP compatibility layers may merge query
		// parameters even when the body itself is JSON.
		if query, err := httpraw.AddParameter(request, "query", payload.Group, rawString); err == nil {
			result = append(result, bindingVariant{request: query, affected: "query:" + payload.Group, source: "query 与 JSON 混合绑定"})
		}
	} else if strings.Contains(ctype, "application/x-www-form-urlencoded") {
		if form, err := httpraw.AddParameter(request, "form", payload.Group, rawString); err == nil {
			result = append(result, bindingVariant{request: form, affected: "form:" + payload.Group, source: "form"})
		}
		if query, err := httpraw.AddParameter(request, "query", payload.Group, rawString); err == nil {
			result = append(result, bindingVariant{request: query, affected: "query:" + payload.Group, source: "query 与 form 混合绑定"})
		}
	} else if strings.Contains(ctype, "multipart/form-data") {
		if multipartRequest, err := httpraw.AddParameter(request, "multipart", payload.Group, rawString); err == nil {
			result = append(result, bindingVariant{request: multipartRequest, affected: "multipart:" + payload.Group, source: "multipart"})
		}
		if extended {
			if query, err := httpraw.AddParameter(request, "query", payload.Group, rawString); err == nil {
				result = append(result, bindingVariant{request: query, affected: "query:" + payload.Group, source: "query 与 multipart 混合绑定"})
			}
		}
	} else if extended {
		if query, err := httpraw.AddParameter(request, "query", payload.Group, rawString); err == nil {
			result = append(result, bindingVariant{request: query, affected: "query:" + payload.Group, source: "query"})
		}
	}
	return result
}

func jsonBindingPaths(body []byte, field string) []string {
	var value any
	if json.Unmarshal(body, &value) != nil {
		return nil
	}
	paths := make([]string, 0, 16)
	var walk func(any, string, int)
	walk = func(node any, prefix string, depth int) {
		if depth > 6 || len(paths) >= 32 {
			return
		}
		switch typed := node.(type) {
		case map[string]any:
			candidate := field
			if prefix != "" {
				candidate = prefix + "." + field
			}
			paths = append(paths, candidate)
			for key, child := range typed {
				next := key
				if prefix != "" {
					next = prefix + "." + key
				}
				walk(child, next, depth+1)
			}
		case []any:
			for index, child := range typed {
				if index >= 8 {
					break
				}
				next := fmt.Sprintf("%s[%d]", prefix, index)
				walk(child, next, depth+1)
			}
		}
	}
	walk(value, "", 0)
	return paths
}

func scalarPayload(raw string) string {
	var value any
	if json.Unmarshal([]byte(raw), &value) != nil {
		return raw
	}
	switch typed := value.(type) {
	case string:
		return typed
	case bool:
		return strconv.FormatBool(typed)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		encoded, _ := json.Marshal(typed)
		return string(encoded)
	}
}
