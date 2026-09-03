package plugin

import (
	"html"
	"strings"

	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/model"
)

type ReflectedXSS struct{}

func (ReflectedXSS) Meta() model.PluginMeta {
	return StandardMeta("reflected_xss", "反射型XSS", "先定位唯一标记的反射上下文，再验证 HTML/属性/脚本上下文关键字符。", "active", true)
}

func (p ReflectedXSS) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	rule := ctx.Rule(meta.ID)
	if !contains([]string{"GET", "POST", "PUT", "PATCH"}, ctx.Request.Method) {
		ctx.Progress(meta.ID, 1, 1)
		return nil, nil
	}
	total := len(ctx.Points) * 2
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
		contextKind := bestReflectionContext(markerResponse.Text(), token)
		if !executableReflectionContext(contextKind) {
			done++
			ctx.Progress(meta.ID, done, total)
			continue
		}
		payloadRule, ok := xssPayloadForContext(payloadsForMode(rule, ctx.Mode), contextKind)
		if !ok {
			done++
			ctx.Progress(meta.ID, done, total)
			continue
		}
		payload := expandPayload(payloadRule.Payload, map[string]string{"token": token, "value": point.Value})
		testReq, err := ctx.Mutate(point, payload)
		if err != nil {
			continue
		}
		testResponse, err := ctx.Send(testReq)
		if err != nil {
			return findings, err
		}
		done++
		ctx.Progress(meta.ID, done, total)
		testContexts := reflectionContexts(testResponse.Text(), token)
		if strings.Contains(testResponse.Text(), payload) && !strings.Contains(testResponse.Text(), html.EscapeString(payload)) &&
			contains(testContexts, contextKind) {
			findings = append(findings, Finding(meta, "输入在可执行 HTML 上下文中未经编码反射", model.SeverityLow, model.ConfidenceFirm, point.Label(),
				"唯一标记确认输入被反射，随后上下文 payload 的关键字符完整进入 "+contextKind+" 上下文。V1 不虚构浏览器执行证据。",
				"按 HTML、属性和 JavaScript 输出上下文编码；不要拼接不可信输入，并部署严格 CSP 作为纵深防御。",
				[]model.Evidence{
					ctx.Evidence("唯一标记被 HTML 响应反射", markerReq, &markerResponse, map[string]any{"context": contextKind, "token": token}),
					ctx.Evidence("上下文 payload 未被编码", testReq, &testResponse, map[string]any{"context": contextKind, "payload_rule": payloadRule.Name, "match": payload}),
				}, "OWASP WSTG-INPV-01"))
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
	prefix := strings.ToLower(body[:at])
	if strings.LastIndex(prefix, "<!--") > strings.LastIndex(prefix, "-->") {
		return "comment"
	}
	if rawElementOpen(prefix, "script") {
		return scriptContextAt(body, at)
	}
	for _, name := range []string{"style", "textarea", "title", "xmp", "noembed", "noframes"} {
		if rawElementOpen(prefix, name) {
			return "inert-text"
		}
	}
	open := strings.LastIndex(prefix, "<")
	close := strings.LastIndex(prefix, ">")
	if open <= close {
		return "html-text"
	}
	tagFragment := body[open:at]
	lowerFragment := strings.ToLower(tagFragment)
	if strings.HasPrefix(lowerFragment, "<!") || strings.HasPrefix(lowerFragment, "<?") ||
		strings.HasPrefix(lowerFragment, "</") {
		return "inert-tag"
	}
	switch quotedAttributeDelimiter(tagFragment) {
	case '"':
		return "attribute-double"
	case '\'':
		return "attribute-single"
	}
	if insideUnquotedAttribute(tagFragment) {
		return "attribute-unquoted"
	}
	return "tag"
}

func rawElementOpen(prefix, name string) bool {
	open := strings.LastIndex(prefix, "<"+name)
	close := strings.LastIndex(prefix, "</"+name)
	return open > close
}

func quotedAttributeDelimiter(fragment string) byte {
	quote := byte(0)
	escaped := false
	for index := 1; index < len(fragment); index++ {
		current := fragment[index]
		if escaped {
			escaped = false
			continue
		}
		if current == '\\' {
			escaped = true
			continue
		}
		if quote == 0 && (current == '"' || current == '\'') {
			quote = current
		} else if current == quote {
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
	script := body[open+start+1 : at]
	quote := byte(0)
	escaped := false
	for index := 0; index < len(script); index++ {
		current := script[index]
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
