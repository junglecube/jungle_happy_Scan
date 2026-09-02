package plugin

import (
	"strings"

	"jungle_happy_Scan/internal/diff"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

type ParameterConfusion struct{}

func (ParameterConfusion) Meta() model.PluginMeta {
	return StandardMeta("parameter_confusion", "HTTP 参数污染与身份优先级混淆", "反转同名参数或会话凭据的先后顺序，识别代理、Spring/CTP、业务层取值规则不一致。", "active", true)
}

type precedenceProbe struct {
	point   httpraw.InsertionPoint
	session bool
	first   *httpraw.Request
	second  *httpraw.Request
}

func (p ParameterConfusion) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	probes := buildPrecedenceProbes(ctx)
	total := len(probes) * 4
	done := 0
	ctx.Progress(meta.ID, 0, max(total, 1))
	var findings []model.Finding
	for _, probe := range probes {
		requests := []*httpraw.Request{probe.first, probe.second, probe.second, probe.first}
		responses := make([]model.Response, 0, 4)
		for _, request := range requests {
			response, err := ctx.Send(request)
			if err != nil {
				return findings, err
			}
			responses = append(responses, response)
			done++
			ctx.Progress(meta.ID, min(done, total), max(total, 1))
		}
		firstOne, secondOne, secondTwo, firstTwo := responses[0], responses[1], responses[2], responses[3]
		if diff.Similarity(firstOne, firstTwo, ctx.Config) < 0.92 || diff.Similarity(secondOne, secondTwo, ctx.Config) < 0.92 {
			continue
		}
		firstBaseline := min(diff.Similarity(ctx.Baseline, firstOne, ctx.Config), diff.Similarity(ctx.Baseline, firstTwo, ctx.Config))
		secondBaseline := max(diff.Similarity(ctx.Baseline, secondOne, ctx.Config), diff.Similarity(ctx.Baseline, secondTwo, ctx.Config))
		orderDifference := max(diff.Similarity(firstOne, secondOne, ctx.Config), diff.Similarity(firstTwo, secondTwo, ctx.Config)) <= 0.68 ||
			firstOne.StatusCode/100 != secondOne.StatusCode/100
		if !orderDifference || firstBaseline < 0.84 || secondBaseline > 0.78 {
			continue
		}
		title := "同名参数顺序改变服务端解析结果"
		severityValue, confidenceValue := model.SeverityMedium, model.ConfidenceFirm
		description := "保持同一组值不变，仅反转同名参数先后顺序，服务端即在两轮测试中稳定返回不同业务结果；其中“原值在后”的响应接近基线。这可能造成网关校验值与 Spring/CTP 实际取值不一致。"
		reference := "CWE-235"
		if probe.session {
			title = "重复会话凭据顺序导致认证优先级混淆"
			severityValue, confidenceValue = model.SeverityHigh, model.ConfidenceCertain
			description = "有效与无效会话值同时出现时，仅反转顺序就稳定改变认证结果；这说明代理、容器或应用对重复凭据的取值优先级不一致，可形成身份校验绕过链。"
			reference = "CWE-441"
		}
		findings = append(findings, Finding(meta, title, severityValue, confidenceValue, probe.point.Label(),
			description,
			"在入口网关拒绝重复安全敏感参数和重复认证凭据；统一 query/form/header/cookie/JSON 的参数来源优先级；业务层使用单值读取并对重复值 fail closed。",
			[]model.Evidence{
				ctx.Evidence("顺序 A：无效值在前、原值在后", probe.first, &firstOne, map[string]any{"baseline_similarity": firstBaseline}),
				ctx.Evidence("顺序 B：原值在前、无效值在后", probe.second, &secondOne, map[string]any{"baseline_similarity": secondBaseline}),
				ctx.Evidence("反向复核顺序 B", probe.second, &secondTwo, nil),
				ctx.Evidence("反向复核顺序 A", probe.first, &firstTwo, nil),
			}, reference))
	}
	ctx.Progress(meta.ID, max(done, total), max(total, 1))
	return findings, nil
}

func buildPrecedenceProbes(ctx *Context) []precedenceProbe {
	const invalid = "jhs_invalid_precedence_731"
	sessionSet := make(map[string]bool)
	for _, key := range ctx.Config.SessionIdentifiers {
		sessionSet[strings.ToLower(strings.TrimSpace(key))] = true
	}
	points := append([]httpraw.InsertionPoint(nil), ctx.Points...)
	points = append(points, httpraw.SessionPoints(ctx.Request, ctx.Config.SessionIdentifiers)...)
	// This plugin has one deterministic capability. Presets only decide whether
	// it is selected; they do not silently halve its coverage.
	limit := 12
	var result []precedenceProbe
	seen := map[string]bool{}
	for _, point := range points {
		key := point.Location + "|" + point.Path
		if seen[key] || len(result) >= limit {
			continue
		}
		isSession := sessionSet[strings.ToLower(point.Name)]
		var first, second *httpraw.Request
		var err error
		switch point.Location {
		case "query", "form":
			first, err = httpraw.DuplicateParameter(ctx.Request, point, invalid, point.Value)
			if err == nil {
				second, err = httpraw.DuplicateParameter(ctx.Request, point, point.Value, invalid)
			}
		case "cookie":
			first = duplicateCookie(ctx.Request, point.Name, invalid, point.Value)
			second = duplicateCookie(ctx.Request, point.Name, point.Value, invalid)
		case "header":
			first = duplicateHeader(ctx.Request, point.Name, invalid, point.Value)
			second = duplicateHeader(ctx.Request, point.Name, point.Value, invalid)
		default:
			continue
		}
		if err == nil && first != nil && second != nil {
			result = append(result, precedenceProbe{point: point, session: isSession, first: first, second: second})
			seen[key] = true
		}
	}
	return result
}

func duplicateCookie(request *httpraw.Request, name, first, second string) *httpraw.Request {
	out := request.Clone()
	for index := range out.Headers {
		if !strings.EqualFold(out.Headers[index].Name, "Cookie") {
			continue
		}
		parts := strings.Split(out.Headers[index].Value, ";")
		for partIndex, part := range parts {
			key, _, ok := strings.Cut(strings.TrimSpace(part), "=")
			if ok && strings.EqualFold(key, name) {
				parts[partIndex] = key + "=" + first + "; " + key + "=" + second
				out.Headers[index].Value = strings.Join(parts, "; ")
				return out
			}
		}
	}
	return nil
}

func duplicateHeader(request *httpraw.Request, name, first, second string) *httpraw.Request {
	out := request.WithoutHeaders(name)
	out.Headers = append(out.Headers, httpraw.Header{Name: name, Value: first}, httpraw.Header{Name: name, Value: second})
	return out
}
