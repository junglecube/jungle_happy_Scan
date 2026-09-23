package plugin

import (
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strings"

	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

var (
	xmlDeclaration = regexp.MustCompile(`(?is)^\s*<\?xml[^>]*\?>`)
	xmlRoot        = regexp.MustCompile(`(?is)<([A-Za-z_][\w:.-]*)(?:\s[^>]*)?>`)
)

type XXE struct{}

func (XXE) Meta() model.PluginMeta {
	return StandardMeta("xxe", "XXE 注入", "使用前台配置的 DTD 模板和响应规则验证实体展开、文件读取和离线回连。", "active", true)
}

func (p XXE) Scan(ctx *Context) ([]model.Finding, error) {
	return scanXXE(ctx, p.Meta())
}

func scanXXE(ctx *Context, meta model.PluginMeta) (findings []model.Finding, scanErr error) {
	body := string(ctx.Request.Body)
	hasNestedXML := false
	for _, point := range ctx.Points {
		if point.Location == "nested_xml" && xxePoint(point) {
			hasNestedXML = true
			break
		}
	}
	if !strings.Contains(ctx.Request.ContentType(), "xml") && !strings.HasPrefix(strings.TrimSpace(body), "<") && !hasNestedXML {
		ctx.Progress(meta.ID, 1, 1)
		return nil, nil
	}
	points := make([]httpraw.InsertionPoint, 0)
	for _, point := range ctx.Points {
		if !xxePoint(point) {
			continue
		}
		document, err := xxeDocument(ctx.Request, point)
		if err != nil {
			continue
		}
		withoutDecl := xmlDeclaration.ReplaceAllString(document, "")
		root := xmlRoot.FindStringSubmatch(withoutDecl)
		if len(root) >= 2 && !strings.Contains(strings.ToUpper(withoutDecl), "<!DOCTYPE") {
			points = append(points, point)
		}
	}
	if len(points) == 0 {
		ctx.Progress(meta.ID, 1, 1)
		return nil, nil
	}
	payloads := payloadsForMode(ctx.Rule(meta.ID), ctx.Mode)
	total := len(payloads) * len(points)
	ctx.Progress(meta.ID, 0, max(total, 1))
	type callbackProbe struct {
		token, rule string
		point       string
		request     *httpraw.Request
		response    model.Response
	}
	pending := make([]callbackProbe, 0)
	defer func() {
		byToken := map[string]callbackProbe{}
		var tokens []string
		for _, probe := range pending {
			byToken[probe.token] = probe
			tokens = append(tokens, probe.token)
		}
		findings = append(findings, settleOAST(ctx, tokens, func(token string, late bool) model.Finding {
			probe := byToken[token]
			return Finding(meta, "XXE 外部实体产生回连", model.SeverityHigh, model.ConfidenceCertain, probe.point,
				"实体探针对应的唯一回连已收到；结合响应及请求证据复核 XML 处理链路。", "禁用外部实体并限制出站访问。",
				[]model.Evidence{ctx.Evidence("收到唯一 XXE 回连", probe.request, &probe.response, map[string]any{"callback": true, "callback_token": token, "payload_rule": probe.rule, "late_callback": late, "evidence_strength": "L5"})}, "OWASP WSTG-INPV-07")
		})...)
	}()

	done := 0
	for _, point := range points {
		originalDocument, err := xxeDocument(ctx.Request, point)
		if err != nil {
			continue
		}
		declaration := xmlDeclaration.FindString(originalDocument)
		withoutDecl := xmlDeclaration.ReplaceAllString(originalDocument, "")
		root := xmlRoot.FindStringSubmatch(withoutDecl)
		if len(root) < 2 {
			continue
		}
		for _, payload := range payloads {
			token := randomID("xxe")
			callbackToken, callbackURL := "", ""
			if payload.Kind == "callback" {
				if ctx.Config.CallbackBaseURL == "" {
					done++
					ctx.Progress(meta.ID, done, total)
					continue
				}
				callbackToken, callbackURL = ctx.Callbacks.Register(ctx.Config.CallbackBaseURL, "xxe")
			}
			replacements := map[string]string{"root": root[1], "token": token, "callback": callbackURL}
			mutatedValue := "&jungle_happy_scan;"
			doctype := xmlDeclaration.ReplaceAllString(expandPayload(payload.Payload, replacements), "")
			if payload.Kind == "inline" {
				var encoded strings.Builder
				for _, ch := range token {
					fmt.Fprintf(&encoded, "&#%d;", ch)
				}
				doctype = strings.ReplaceAll(doctype, token, encoded.String())
			}
			if payload.Kind == "xinclude_file" {
				mutatedValue = expandPayload(payload.Payload, replacements)
				doctype = ""
			}
			mutated, err := ctx.Mutate(point, mutatedValue)
			if point.Location == "xml_cdata" {
				mutated, err = mutateXXECDATA(ctx.Request, point, mutatedValue)
			}
			if err != nil {
				done++
				ctx.Progress(meta.ID, done, total)
				continue
			}
			documentBody, documentErr := xxeDocument(mutated, point)
			if documentErr != nil {
				ctx.ResolveMutationFailed(1)
				done++
				ctx.Progress(meta.ID, done, total)
				continue
			}
			documentBody = xmlDeclaration.ReplaceAllString(documentBody, "")
			document := declaration
			if declaration != "" {
				document += "\n"
			}
			if doctype != "" {
				document += doctype + "\n"
			}
			document += documentBody
			if !validXXEDocument(document) {
				ctx.ResolveMutationFailed(1)
				done++
				ctx.Progress(meta.ID, done, total)
				continue
			}
			request := mutated.WithBody([]byte(document))
			if point.Location == "nested_xml" {
				request, err = httpraw.MutateNestedXMLDocument(mutated, point, document)
				if err != nil {
					ctx.ResolveMutationFailed(1)
					done++
					ctx.Progress(meta.ID, done, total)
					continue
				}
			}
			response, sendErr := ctx.Send(request)
			if payload.Kind == "callback" {
				pending = append(pending, callbackProbe{token: callbackToken, rule: payload.Name, point: point.Label(), request: request, response: response})
			}
			if sendErr != nil {
				return findings, sendErr
			}
			done++
			ctx.Progress(meta.ID, done, total)
			if payload.Kind == "callback" {
				continue
			}
			expectedText := expandPayload(payload.Expected, replacements)
			expected, compileErr := regexp.Compile(expectedText)
			if expectedText == "" || compileErr != nil || !expected.Match(response.Body) || expected.Match(ctx.Baseline.Body) {
				continue
			}
			severityValue, confidenceValue, title := model.SeverityHigh, model.ConfidenceFirm, "XML 解析器允许 DTD 实体展开"
			if payload.Kind == "file" || payload.Kind == "xinclude_file" {
				severityValue, confidenceValue, title = model.SeverityHigh, model.ConfidenceCertain, "XML 输入可读取服务端本地文件"
			}
			findings = append(findings, Finding(meta, title, severityValue, confidenceValue, point.Label(),
				"仅变异一个 XML 节点后，服务端响应匹配规则 "+payload.Name+"；其他节点、命名空间和 SOAP 结构均保持原样。",
				"禁用 DTD、外部实体与 XInclude，并限制 XML 解析器的文件和网络访问。",
				[]model.Evidence{ctx.Evidence("精确节点变异匹配 "+payload.Name, request, &response, map[string]any{"match": string(expected.Find(response.Body)), "payload_rule": payload.Name, "xml_point": point.Path, "evidence_strength": "L4"})}, "OWASP WSTG-INPV-07"))
		}
	}
	return findings, nil
}

func xxeDocument(request *httpraw.Request, point httpraw.InsertionPoint) (string, error) {
	if point.Location == "nested_xml" {
		return httpraw.NestedXMLValue(request, point)
	}
	if point.Location == "xml" || point.Location == "xml_cdata" {
		return string(request.Body), nil
	}
	return "", fmt.Errorf("不支持的 XXE 插入点 %q", point.Location)
}

func xxePoint(point httpraw.InsertionPoint) bool {
	if point.Location == "xml" || point.Location == "xml_cdata" {
		return true
	}
	return point.Location == "nested_xml" &&
		(httpraw.NestedXMLLeafLocation(point) == "xml" || httpraw.NestedXMLLeafLocation(point) == "xml_cdata")
}

// CDATA is a container, not an entity expansion sink: replace the chosen
// container only, leaving identically-valued sibling nodes untouched.
func mutateXXECDATA(request *httpraw.Request, point httpraw.InsertionPoint, value string) (*httpraw.Request, error) {
	re := regexp.MustCompile(`(?s)<!\[CDATA\[.*?\]\]>`)
	matches := re.FindAllIndex(request.Body, -1)
	var index int
	if _, err := fmt.Sscan(point.Path, &index); err != nil || index < 0 || index >= len(matches) {
		return nil, fmt.Errorf("CDATA 插入点无效")
	}
	at := matches[index]
	body := append([]byte(nil), request.Body[:at[0]]...)
	body = append(body, []byte(value)...)
	body = append(body, request.Body[at[1]:]...)
	return request.WithBody(body), nil
}
func validXXEDocument(document string) bool {
	decoder := xml.NewDecoder(strings.NewReader(document))
	decoder.Strict = false
	roots, depth := 0, 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return roots == 1 && depth == 0
		}
		if err != nil {
			return false
		}
		switch token.(type) {
		case xml.StartElement:
			if depth == 0 {
				roots++
			}
			depth++
		case xml.EndElement:
			depth--
		}
	}
}
