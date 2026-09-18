package plugin

import (
	"regexp"
	"strings"

	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/model"
)

type ReflectedXSS struct{}
type ReflectedXSSDeep struct{}

func (ReflectedXSS) Meta() model.PluginMeta {
	meta := StandardMeta("reflected_xss", "反射型 XSS（快速）", "先定位唯一标记，再使用少量常见 HTML、属性和脚本 Payload 验证反射型 XSS。", "active", true)
	meta.Version = "3.11.0"
	return meta
}

func (ReflectedXSSDeep) Meta() model.PluginMeta {
	meta := StandardMeta("reflected_xss_deep", "反射型 XSS（深度）", "包含快速 Payload，并增加 img/onerror、details/ontoggle、无引号、反引号和 JavaScript 一行式变体。", "active", true)
	meta.Version = "3.11.0"
	return meta
}

func (p ReflectedXSS) Scan(ctx *Context) ([]model.Finding, error) {
	return scanReflectedXSS(ctx, p.Meta(), "reflected_xss")
}

func (p ReflectedXSSDeep) Scan(ctx *Context) ([]model.Finding, error) {
	return scanReflectedXSS(ctx, p.Meta(), "reflected_xss_deep")
}

func scanReflectedXSS(ctx *Context, meta model.PluginMeta, ruleID string) ([]model.Finding, error) {
	rule := ctx.Rule(ruleID)
	if !contains([]string{"GET", "POST", "PUT", "PATCH"}, ctx.Request.Method) {
		ctx.Progress(meta.ID, 1, 1)
		return nil, nil
	}
	total := len(ctx.Points) * xssRequestEstimate(payloadsForMode(rule, ctx.Mode))
	done := 0
	ctx.Progress(meta.ID, done, max(total, 1))
	var findings []model.Finding
	for _, point := range ctx.Points {
		token := randomID("xss")
		markerReq, err := ctx.Mutate(point, token)
		if err != nil {
			continue
		}
		markerResponse, err := ctx.Send(markerReq)
		if err != nil {
			return findings, err
		}
		done++
		ctx.Progress(meta.ID, done, total)
		contentType := strings.ToLower(markerResponse.Header("Content-Type"))
		if !strings.Contains(markerResponse.Text(), token) || !xssHTMLResponse(contentType, markerResponse.Text()) {
			done++
			ctx.Progress(meta.ID, done, total)
			continue
		}
		seen := map[string]bool{}
		for _, contextKind := range reflectionContexts(markerResponse.Text(), token) {
			if seen[contextKind] {
				continue
			}
			seen[contextKind] = true
			candidates := xssCandidates(payloadsForMode(rule, ctx.Mode), contextKind)
			for _, payloadRule := range candidates {
				payload := expandPayload(payloadRule.Payload, map[string]string{"token": token, "value": point.Value})
				testReq, err := ctx.Mutate(point, payload)
				if err != nil {
					ctx.ResolveMutationFailed(1)
					continue
				}
				testResponse, err := ctx.Send(testReq)
				if err != nil {
					return findings, err
				}
				done++
				ctx.Progress(meta.ID, done, total)
				if !xssHTMLResponse(strings.ToLower(testResponse.Header("Content-Type")), testResponse.Text()) {
					continue
				}
				// Assess each raw payload occurrence in its own original context.
				// An encoded copy elsewhere must not veto this occurrence.
				matched := false
				matchOffset := -1
				offset := 0
				for offset < len(testResponse.Text()) {
					relative := strings.Index(testResponse.Text()[offset:], payload)
					if relative < 0 {
						break
					}
					at := offset + relative
					if htmlContextAt(testResponse.Text(), at) == contextKind {
						matched = true
						matchOffset = at
						break
					}
					offset = at + len(payload)
				}
				if !matched {
					continue
				}
				csp := assessXSSCSP(testResponse, payload)
				visibility := xssVisibilityContext(testResponse.Text(), matchOffset)
				title := "输入在 HTML 上下文中未经编码反射"
				description := "唯一标记与上下文闭合 payload 在同一反射位置完整出现；尚未取得浏览器执行证据。"
				if csp.BlocksInline {
					title += "（当前 Payload 受 CSP 缓解）"
					description += " 响应中的强制 CSP 策略会阻断本次内联脚本/事件 Payload；这不等于所有 XSS 传播路径均不存在。"
				}
				findings = append(findings, Finding(meta, title, model.SeverityLow, model.ConfidenceFirm, point.Label(),
					description,
					"按 HTML、属性和 JavaScript 输出上下文编码，避免将不可信内容拼接为源码。",
					[]model.Evidence{ctx.Evidence("唯一标记定位反射位置", markerReq, &markerResponse, map[string]any{"context": contextKind, "token": token}), ctx.Evidence("当前反射位置保留完整 payload", testReq, &testResponse, map[string]any{"context": contextKind, "payload_rule": payloadRule.Name, "match": payload, "visibility": visibility, "csp_present": csp.Present, "csp_report_only": csp.ReportOnly, "csp_blocks_inline": csp.BlocksInline, "csp_directive": csp.Directive})}, "OWASP WSTG-INPV-01"))
				break
			}
		}
	}
	return findings, nil
}

func xssPayloadForContext(payloads []config.PayloadRule, contextKind string) (config.PayloadRule, bool) {
	for _, payload := range payloads {
		if payload.Kind == contextKind {
			return payload, true
		}
	}
	fallback := contextKind
	if strings.HasPrefix(contextKind, "attribute-") {
		fallback = "attribute"
	} else if strings.HasPrefix(contextKind, "script-") {
		fallback = "script"
	}
	for _, payload := range payloads {
		if payload.Kind == fallback {
			return payload, true
		}
	}
	for _, payload := range payloads {
		if payload.Kind == "html-text" {
			return payload, true
		}
	}
	return config.PayloadRule{}, false
}

func xssHTMLResponse(contentType, body string) bool {
	if strings.Contains(contentType, "json") || strings.Contains(contentType, "xml") {
		return false
	}
	// A text/plain response is not promoted to reflected XSS solely because its
	// bytes look like HTML. Missing/ambiguous MIME is assessed separately by
	// security_headers and requires nosniff evidence.
	if strings.Contains(contentType, "text/plain") {
		return false
	}
	if strings.Contains(contentType, "html") || strings.Contains(contentType, "x-jsp") {
		return true
	}
	prefix := strings.ToLower(strings.TrimSpace(body))
	return strings.HasPrefix(prefix, "<!doctype html") || strings.HasPrefix(prefix, "<html")
}

func executableReflectionContext(kind string) bool {
	return kind == "html-text" || kind == "attribute" || kind == "script" || kind == "tag" ||
		strings.HasPrefix(kind, "attribute-") || strings.HasPrefix(kind, "script-")
}

func bestReflectionContext(body, token string) string {
	contexts := reflectionContexts(body, token)
	for _, preferred := range []string{
		"script-single", "script-double", "script-template", "script-code", "script",
		"attribute-double", "attribute-single", "attribute-unquoted", "attribute",
		"tag", "html-text",
	} {
		if contains(contexts, preferred) {
			return preferred
		}
	}
	if len(contexts) > 0 {
		return contexts[0]
	}
	return "not-reflected"
}

// reflectionContexts classifies every occurrence rather than trusting the
// first reflection. It deliberately marks comments and raw-text containers as
// inert so a payload echoed in diagnostics, textarea or style content is not
// reported as executable XSS.
func reflectionContexts(body, token string) []string {
	var contexts []string
	offset := 0
	for {
		relative := strings.Index(body[offset:], token)
		if relative < 0 {
			break
		}
		at := offset + relative
		contexts = append(contexts, htmlContextAt(body, at))
		offset = at + len(token)
	}
	return contexts
}

func htmlContextAt(body string, at int) string {
	lower := strings.ToLower(body)
	raw := ""
	for i := 0; i < at; {
		if raw != "" {
			end := strings.Index(lower[i:], "</"+raw)
			if end < 0 || i+end >= at {
				if raw == "script" {
					return scriptContextAt(body, at)
				}
				return "raw-" + raw
			}
			i += end
			raw = ""
		}
		if strings.HasPrefix(lower[i:], "<!--") {
			end := strings.Index(lower[i+4:], "-->")
			if end < 0 || i+4+end >= at {
				return "comment"
			}
			i += 4 + end + 3
			continue
		}
		if body[i] != '<' {
			i++
			continue
		}
		start := i
		i++
		quote := byte(0)
		for i < at {
			ch := body[i]
			if quote != 0 {
				if ch == quote {
					quote = 0
				}
			} else if ch == '\'' || ch == '"' {
				quote = ch
			} else if ch == '>' {
				break
			}
			i++
		}
		fragment := body[start:at]
		if i == at {
			if strings.HasPrefix(fragment, "</") || strings.HasPrefix(fragment, "<!") || strings.HasPrefix(fragment, "<?") {
				return "inert-tag"
			}
			if quote == '"' {
				return "attribute-double"
			}
			if quote == '\'' {
				return "attribute-single"
			}
			if insideUnquotedAttribute(fragment) {
				return "attribute-unquoted"
			}
			return "tag"
		}
		tag := strings.Fields(strings.TrimSpace(lower[start+1 : i]))
		if len(tag) > 0 {
			switch tag[0] {
			case "script", "style", "textarea", "title", "xmp", "noembed", "noframes":
				raw = tag[0]
			}
		}
		i++
	}
	return "html-text"
}

func rawElementOpen(prefix, name string) bool {
	open := strings.LastIndex(prefix, "<"+name)
	close := strings.LastIndex(prefix, "</"+name)
	return open > close
}

func quotedAttributeDelimiter(fragment string) byte {
	quote := byte(0)
	for i := 1; i < len(fragment); i++ {
		c := fragment[i]
		if quote == 0 && (c == '"' || c == '\'') {
			quote = c
		} else if c == quote {
			quote = 0
		}
	}
	return quote
}

func insideUnquotedAttribute(fragment string) bool {
	lastSpace := strings.LastIndexAny(fragment, " \t\r\n")
	tail := fragment[lastSpace+1:]
	equal := strings.IndexByte(tail, '=')
	return equal > 0 && equal < len(tail)-1 && !strings.ContainsAny(tail[equal+1:], "\"'")
}

func scriptContextAt(body string, at int) string {
	lowerPrefix := strings.ToLower(body[:at])
	open := strings.LastIndex(lowerPrefix, "<script")
	if open < 0 {
		return "script-code"
	}
	start := strings.Index(body[open:at], ">")
	if start < 0 {
		return "script"
	}
	tag := strings.ToLower(body[open : open+start+1])
	typeMatch := regexp.MustCompile(`(?i)\btype\s*=\s*["']?([^"'\s>]+)`).FindStringSubmatch(tag)
	if len(typeMatch) == 2 && typeMatch[1] != "module" && !strings.Contains(typeMatch[1], "javascript") && !strings.Contains(typeMatch[1], "ecmascript") {
		return "raw-script"
	}
	script := body[open+start+1 : at]
	quote := byte(0)
	escaped := false
	lineComment, blockComment := false, false
	for index := 0; index < len(script); index++ {
		current := script[index]
		if lineComment {
			if current == '\n' || current == '\r' {
				lineComment = false
			}
			continue
		}
		if blockComment {
			if current == '*' && index+1 < len(script) && script[index+1] == '/' {
				blockComment = false
				index++
			}
			continue
		}
		if quote == 0 && current == '/' && index+1 < len(script) {
			if script[index+1] == '/' {
				lineComment = true
				index++
				continue
			}
			if script[index+1] == '*' {
				blockComment = true
				index++
				continue
			}
		}
		if escaped {
			escaped = false
			continue
		}
		if current == '\\' {
			escaped = true
			continue
		}
		if quote == 0 && (current == '\'' || current == '"' || current == '`') {
			quote = current
		} else if current == quote {
			quote = 0
		}
	}
	if lineComment {
		return "script-comment-line"
	}
	if blockComment {
		return "script-comment-block"
	}
	switch quote {
	case '\'':
		return "script-single"
	case '"':
		return "script-double"
	case '`':
		return "script-template"
	default:
		return "script-code"
	}
}

func xssCandidates(payloads []config.PayloadRule, kind string) []config.PayloadRule {
	var result []config.PayloadRule
	for _, p := range payloads {
		if p.Kind == kind {
			if kind == "script-code" && strings.HasPrefix(p.Payload, "{{token}};") {
				p.Payload = strings.Replace(p.Payload, "{{token}};", "/*{{token}}*/;", 1)
			}
			result = append(result, p)
		}
	}
	if len(result) == 0 && executableReflectionContext(kind) && !strings.HasPrefix(kind, "script-comment") {
		if p, ok := xssPayloadForContext(payloads, kind); ok {
			result = append(result, p)
		}
	}
	prefix := ""
	if strings.HasPrefix(kind, "raw-") {
		prefix = "</" + strings.TrimPrefix(kind, "raw-") + ">"
	}
	if kind == "comment" {
		prefix = "-->"
	}
	if strings.HasPrefix(kind, "script-") {
		prefix = "</script>"
	}
	if prefix != "" {
		result = append(result, config.PayloadRule{Name: "上下文闭合", Kind: kind, Payload: prefix + `{{token}}<svg/onload=confirm("{{token}}")>`})
	}
	// Some HTML/XML serializers escape or rewrite quotes while leaving angle
	// brackets intact. A quote-free probe keeps the executable markup valid in
	// embedded JSON/XML text nodes such as <Field>{"value":"..."}</Field>.
	if kind == "html-text" || kind == "tag" {
		result = append(result, config.PayloadRule{Name: "无引号 HTML 标签", Kind: kind, Payload: `{{token}}<svg/onload=confirm(1)>`})
	}
	return result
}

type xssCSPAssessment struct {
	Present      bool
	ReportOnly   bool
	BlocksInline bool
	Directive    string
}

// assessXSSCSP evaluates only the tested inline script/event vector. CSP is a
// mitigation signal, not a reason to discard a reflection finding: another
// browser context or a different policy can still leave the sink exploitable.
func assessXSSCSP(response model.Response, payload string) xssCSPAssessment {
	policy := strings.TrimSpace(response.Header("Content-Security-Policy"))
	if policy == "" {
		return xssCSPAssessment{ReportOnly: strings.TrimSpace(response.Header("Content-Security-Policy-Report-Only")) != ""}
	}
	result := xssCSPAssessment{Present: true}
	directives := make(map[string][]string)
	for _, raw := range strings.Split(policy, ";") {
		fields := strings.Fields(strings.TrimSpace(raw))
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		directives[name] = fields[1:]
	}
	lookup := []string{"script-src-attr", "script-src", "default-src"}
	if strings.Contains(strings.ToLower(payload), "<script") {
		lookup = []string{"script-src-elem", "script-src", "default-src"}
	}
	for _, name := range lookup {
		sources, ok := directives[name]
		if !ok {
			continue
		}
		result.Directive = name
		for _, source := range sources {
			if strings.EqualFold(source, "'unsafe-inline'") {
				return result
			}
		}
		// A nonce/hash would need to be present on the injected element and is
		// therefore not usable by this static payload. Any declared script
		// source list without unsafe-inline blocks this inline vector.
		result.BlocksInline = true
		return result
	}
	return result
}

func xssVisibilityContext(body string, at int) string {
	if at < 0 || at > len(body) {
		return "unknown"
	}
	prefix := body[:at]
	if open := strings.LastIndex(prefix, "<"); open > strings.LastIndex(prefix, ">") {
		fragment := strings.ToLower(prefix[open:])
		if strings.HasPrefix(fragment, "<input") && regexp.MustCompile(`\btype\s*=\s*["']?hidden\b`).MatchString(fragment) {
			return "hidden-input"
		}
		if regexp.MustCompile(`\bstyle\s*=\s*["'][^"']*display\s*:\s*none`).MatchString(fragment) {
			return "display-none-attribute"
		}
	}
	// Track already-open elements for the common hidden/display:none wrapper
	// case. Visibility is metadata only; CSS/hidden does not suppress an HTML
	// parser executing a newly injected script-capable element.
	tagRE := regexp.MustCompile(`(?is)<(/?)([a-z][\w:-]*)([^>]*)>`)
	stack := []struct {
		name   string
		hidden bool
	}{}
	for _, match := range tagRE.FindAllStringSubmatch(prefix, -1) {
		if match[1] == "/" {
			for i := len(stack) - 1; i >= 0; i-- {
				if stack[i].name == strings.ToLower(match[2]) {
					stack = stack[:i]
					break
				}
			}
			continue
		}
		attrs := strings.ToLower(match[3])
		hidden := strings.Contains(attrs, " hidden") || strings.HasPrefix(attrs, "hidden") ||
			regexp.MustCompile(`\bstyle\s*=\s*["'][^"']*display\s*:\s*none`).MatchString(attrs)
		stack = append(stack, struct {
			name   string
			hidden bool
		}{strings.ToLower(match[2]), hidden})
	}
	for _, item := range stack {
		if item.hidden {
			return "hidden-ancestor"
		}
	}
	return "visible"
}

func xssRequestEstimate(payloads []config.PayloadRule) int {
	count := 1
	for _, kind := range []string{"html-text", "attribute-single", "attribute-double", "attribute-unquoted", "tag", "script-single", "script-double", "script-template", "script-code", "script", "script-comment-line", "script-comment-block", "raw-script", "raw-style", "raw-textarea", "raw-title", "raw-xmp", "raw-noembed", "raw-noframes", "comment"} {
		count += len(xssCandidates(payloads, kind))
	}
	return count
}
