package plugin

import (
	"regexp"
	"strings"
	"time"

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

func scanXXE(ctx *Context, meta model.PluginMeta) ([]model.Finding, error) {
	body := string(ctx.Request.Body)
	if !strings.Contains(ctx.Request.ContentType(), "xml") && !strings.HasPrefix(strings.TrimSpace(body), "<") {
		ctx.Progress(meta.ID, 1, 1)
		return nil, nil
	}
	declaration := xmlDeclaration.FindString(body)
	withoutDecl := xmlDeclaration.ReplaceAllString(body, "")
	root := xmlRoot.FindStringSubmatch(withoutDecl)
	if len(root) < 2 || strings.Contains(strings.ToUpper(withoutDecl), "<!DOCTYPE") {
		ctx.Progress(meta.ID, 1, 1)
		return nil, nil
	}
	points := make([]httpraw.InsertionPoint, 0)
	for _, point := range ctx.Points {
		if point.Location == "xml" || point.Location == "xml_cdata" {
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
		request     *httpraw.Request
		response    model.Response
	}
	pending := make([]callbackProbe, 0)
	var findings []model.Finding
	done := 0
	for _, point := range points {
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
			doctype := expandPayload(payload.Payload, replacements)
			if payload.Kind == "xinclude_file" {
				mutatedValue = expandPayload(payload.Payload, replacements)
				doctype = ""
			}
			mutated, err := ctx.Mutate(point, mutatedValue)
			if err != nil {
				done++
				ctx.Progress(meta.ID, done, total)
				continue
			}
			documentBody := xmlDeclaration.ReplaceAllString(string(mutated.Body), "")
			document := declaration
			if declaration != "" {
				document += "\n"
			}
			if doctype != "" {
				document += doctype + "\n"
			}
			document += documentBody
			request := mutated.WithBody([]byte(document))
			response, sendErr := ctx.Send(request)
			if sendErr != nil {
				return findings, sendErr
			}
			done++
			ctx.Progress(meta.ID, done, total)
			if payload.Kind == "callback" {
				pending = append(pending, callbackProbe{token: callbackToken, rule: payload.Name, request: request, response: response})
				continue
			}
			expectedText := expandPayload(payload.Expected, replacements)
			expected, compileErr := regexp.Compile(expectedText)
			if compileErr != nil || !expected.Match(response.Body) || expected.Match(ctx.Baseline.Body) {
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
	tokens := make([]string, 0, len(pending))
	for _, candidate := range pending {
		tokens = append(tokens, candidate.token)
	}
	hits := waitCallbackBatch(ctx.Context, ctx.Callbacks, tokens, 8*time.Second)
	for _, candidate := range pending {
		if !hits[candidate.token] {
			continue
		}
		findings = append(findings, Finding(meta, "XXE 外部实体产生离线回连", model.SeverityHigh, model.ConfidenceCertain, "body:xml",
			"服务端 XML 解析器访问了配置 payload 中的唯一回连 URL。",
			"禁用所有外部实体解析并限制应用服务器出站网络。",
			[]model.Evidence{ctx.Evidence("收到唯一 XXE 回连 token", candidate.request, &candidate.response, map[string]any{"callback": true, "callback_token": candidate.token, "payload_rule": candidate.rule, "evidence_strength": "L5"})}, "OWASP WSTG-INPV-07"))
	}
	return findings, nil
}
