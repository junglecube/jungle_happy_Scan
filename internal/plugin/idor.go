package plugin

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"jungle_happy_Scan/internal/diff"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

type IDOR struct{}

func (IDOR) Meta() model.PluginMeta {
	return StandardMeta("idor", "IDOR 对象越权", "对配置的资源标识参数执行邻值变异，识别结构相似但内容不同的有效对象响应。", "state-changing", true)
}

func (p IDOR) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	rule := ctx.Rule(meta.ID)
	points := make([]httpraw.InsertionPoint, 0)
	for _, point := range ctx.Points {
		if semanticName(point.Name, rule.ParameterNames) && isUnsignedInteger(point.Value) {
			points = append(points, point)
		}
	}
	total := len(points) * 2
	ctx.Progress(meta.ID, 0, max(total, 1))
	done := 0
	var findings []model.Finding
	for _, point := range points {
		original, _ := strconv.ParseUint(point.Value, 10, 64)
		candidates := []uint64{original + 1}
		if original > 0 {
			candidates = append(candidates, original-1)
		} else {
			candidates = append(candidates, original+2)
		}
		for _, candidate := range candidates {
			candidateText := strconv.FormatUint(candidate, 10)
			request, err := ctx.Mutate(point, candidateText)
			if err != nil {
				done++
				continue
			}
			response, err := ctx.Send(request)
			if err != nil {
				return findings, err
			}
			done++
			ctx.Progress(meta.ID, done, total)
			similarity := diff.Similarity(ctx.Baseline, response, ctx.Config)
			mentionsCandidate := responseMentionsID(response.Text(), point.Name, candidateText)
			sameResponse := diff.Normalize(ctx.Baseline, ctx.Config) == diff.Normalize(response, ctx.Config)
			if response.StatusCode >= 400 || diff.LikelyAuthDenied(response, ctx.Config) || similarity < 0.45 || sameResponse || (!mentionsCandidate && similarity >= 0.98) || len(response.Body) < 40 {
				continue
			}
			confidenceValue := model.ConfidenceTentative
			if mentionsCandidate {
				confidenceValue = model.ConfidenceFirm
			}
			findings = append(findings, Finding(meta, "邻近资源标识返回另一份有效数据", model.SeverityHigh, confidenceValue, point.Label(),
				"修改对象标识后返回了结构相似但内容不同的数据，必须结合测试账号权限人工复核。",
				"对每次对象访问校验所有权、租户和角色关系；不要使用不可猜测 ID 代替授权。",
				[]model.Evidence{ctx.Evidence("变更对象 ID 后返回业务数据", request, &response, map[string]any{"similarity": similarity, "original": point.Value, "candidate": candidateText})}, "OWASP WSTG-ATHZ-04"))
			break
		}
	}
	return findings, nil
}

func semanticName(name string, configured []string) bool {
	lower := strings.ToLower(name)
	for _, candidate := range configured {
		candidate = strings.ToLower(strings.TrimSpace(candidate))
		if lower == candidate || (len(candidate) > 2 && strings.HasSuffix(lower, candidate)) {
			return true
		}
	}
	return false
}

// controlledSemanticName expands the conservative exact/suffix matcher only
// for parameter families whose wire names commonly carry harmless wrappers or
// indexes (phonekey, filename1, file_name[0], pathValue). It deliberately
// requires a known modifier after/before the configured term, avoiding a
// broad substring match that would spray state-changing endpoints.
func controlledSemanticName(name string, configured []string) bool {
	nameCompact := semanticNameCompact(name)
	if nameCompact == "" {
		return false
	}
	for _, rawCandidate := range configured {
		candidate := semanticNameCompact(rawCandidate)
		if candidate == "" {
			continue
		}
		if nameCompact == candidate {
			return true
		}
		if strings.HasPrefix(nameCompact, candidate) && semanticModifier(nameCompact[len(candidate):]) {
			return true
		}
		if strings.HasSuffix(nameCompact, candidate) && semanticModifier(nameCompact[:len(nameCompact)-len(candidate)]) {
			return true
		}
	}
	return false
}

func semanticNameCompact(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	var builder strings.Builder
	for _, r := range value {
		if unicode.IsLetter(r) {
			builder.WriteRune(unicode.ToLower(r))
			continue
		}
		if unicode.IsDigit(r) {
			builder.WriteRune(r)
			continue
		}
		// Separators are ignored so file_name, file-name and file.name share
		// the same semantic form.
	}
	compact := builder.String()
	compact = strings.TrimRightFunc(compact, unicode.IsDigit)
	return compact
}

func semanticModifier(value string) bool {
	if value == "" {
		return true
	}
	for _, modifier := range []string{
		"key", "no", "num", "number", "id", "ids", "value", "values", "val",
		"field", "fields", "param", "parameter", "input", "name", "index", "idx",
		"code", "type", "data", "list", "array", "text", "request", "response",
		"source", "target", "download", "upload", "receiver", "sender", "mobile", "phone",
		"file", "path", "template", "resource", "document", "attachment", "filename", "filepath", "backup", "sms",
	} {
		if value == modifier {
			return true
		}
	}
	return false
}

func isUnsignedInteger(value string) bool {
	if value == "" || len(value) > 19 {
		return false
	}
	_, err := strconv.ParseUint(value, 10, 64)
	return err == nil
}

func responseMentionsID(body, name, candidate string) bool {
	pattern := `(?i)["']?` + regexp.QuoteMeta(name) + `["']?\s*[:=]\s*["']?` + regexp.QuoteMeta(candidate) + `(?:["']|\b)`
	return regexp.MustCompile(pattern).MatchString(body)
}
