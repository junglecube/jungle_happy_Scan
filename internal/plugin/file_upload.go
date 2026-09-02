package plugin

import (
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

type FileUpload struct{}

func (FileUpload) Meta() model.PluginMeta {
	return StandardMeta("file_upload", "危险文件上传", "保留原文件内容，使用前台配置的文件名、MIME 和成功规则测试危险上传。", "state-changing", true)
}

func (p FileUpload) Scan(ctx *Context) ([]model.Finding, error) {
	return scanFileUpload(ctx, p.Meta())
}

func scanFileUpload(ctx *Context, meta model.PluginMeta) ([]model.Finding, error) {
	files := ctx.Request.MultipartFiles()
	if len(files) == 0 {
		ctx.Progress(meta.ID, 1, 1)
		return nil, nil
	}
	variants := payloadsForMode(ctx.Rule(meta.ID), ctx.Mode)
	total := 0
	for _, file := range files {
		attempts := 1
		if multipartFieldNameLooksLikeFilename(file.FieldName) {
			attempts = 2
		}
		total += len(variants) * attempts
	}
	ctx.Progress(meta.ID, 0, max(total, 1))
	var findings []model.Finding
	done := 0
	for _, file := range files {
		for _, variant := range variants {
			token := randomID("SAFE_UPLOAD_CANARY")
			filename := expandPayload(variant.Payload, map[string]string{"token": token})
			content := []byte(token)
			executionExpected := ""
			if variant.Kind == "execute_canary" {
				left, right := commandOperands()
				executionExpected = strconv.FormatInt(left*right, 10)
				// The product is intentionally absent from the uploaded source. Serving
				// source code therefore cannot be mistaken for JSP execution.
				content = []byte("<%@ page contentType=\"text/plain\" %><%=" + strconv.FormatInt(left, 10) + "*" + strconv.FormatInt(right, 10) + "%>")
			}
			contentReplaced := variant.Kind == "execute_canary"
			var request *httpraw.Request
			var err error
			if contentReplaced {
				request, err = httpraw.MutateMultipartFileAt(ctx.Request, file.Index, filename, variant.Mime, content)
			} else {
				request, err = httpraw.MutateMultipartFileMetadataAt(ctx.Request, file.Index, filename, variant.Mime)
			}
			if err != nil {
				return findings, err
			}
			response, err := ctx.Send(request)
			if err != nil {
				return findings, err
			}
			done++
			ctx.Progress(meta.ID, done, total)
			expected, _ := regexp.Compile(variant.Expected)
			tokenWasSent := contentReplaced || strings.Contains(filename, token)
			renamedEvidence, renamedAccepted, accepted := uploadAccepted(ctx, response, filename, token, tokenWasSent, expected)
			legacyFieldMutation := false
			if multipartFieldNameLooksLikeFilename(file.FieldName) {
				if !accepted {
					var legacyRequest *httpraw.Request
					var mutateErr error
					if contentReplaced {
						legacyRequest, mutateErr = httpraw.MutateMultipartFileIdentityAt(ctx.Request, file.Index, filename, filename, variant.Mime, content)
					} else {
						legacyRequest, mutateErr = httpraw.MutateMultipartFileIdentityMetadataAt(ctx.Request, file.Index, filename, filename, variant.Mime)
					}
					if mutateErr != nil {
						return findings, mutateErr
					}
					legacyResponse, sendErr := ctx.Send(legacyRequest)
					if sendErr != nil {
						return findings, sendErr
					}
					done++
					ctx.Progress(meta.ID, done, total)
					legacyEvidence, legacyRenamed, legacyAccepted := uploadAccepted(ctx, legacyResponse, filename, token, tokenWasSent, expected)
					if legacyAccepted {
						request, response = legacyRequest, legacyResponse
						renamedEvidence, renamedAccepted, accepted = legacyEvidence, legacyRenamed, true
						legacyFieldMutation = true
					}
				} else {
					// The adaptive compatibility request was unnecessary, but its
					// planned check is complete.
					done++
					ctx.Progress(meta.ID, done, total)
				}
			}
			if !accepted {
				continue
			}
			confidenceValue := model.ConfidenceTentative
			severityValue := model.SeverityMedium
			description := "扫描器保留原文件内容，仅改变文件名/MIME；服务端返回了配置的上传成功证据。该结果证明危险文件类型可被接受，但不等同于远程代码执行。"
			if contentReplaced {
				description = "服务端对无害执行确认文件返回了配置的上传成功证据；后续仍需同源读取验证。"
			}
			if renamedAccepted || strings.Contains(response.Text(), filename) ||
				tokenWasSent && strings.Contains(response.Text(), token) || uploadedResourcePath(response) != "" {
				confidenceValue = model.ConfidenceFirm
				severityValue = model.SeverityHigh
			}
			metrics := map[string]any{
				"filename": filename, "mime": variant.Mime, "payload_rule": variant.Name,
				"file_field": file.FieldName, "file_index": file.Index, "original_filename": file.Filename,
				"legacy_field_name_mutation": legacyFieldMutation, "original_content_preserved": !contentReplaced,
			}
			if tokenWasSent {
				metrics["canary"] = token
			}
			if renamedAccepted {
				metrics["renamed_filename_evidence"] = renamedEvidence
			}
			evidence := []model.Evidence{ctx.Evidence("危险文件名和 MIME 组合被接受", request, &response, metrics)}
			if uploadedPath := uploadedResourcePath(response); uploadedPath != "" {
				verify := ctx.Request.ReplaceTarget(uploadedPath)
				verifyResponse, verifyErr := ctx.Send(verify)
				if verifyErr == nil && verifyResponse.StatusCode >= 200 && verifyResponse.StatusCode < 300 && executionExpected != "" &&
					strings.Contains(verifyResponse.Text(), executionExpected) && !strings.Contains(verifyResponse.Text(), "<%=") {
					confidenceValue = model.ConfidenceCertain
					severityValue = model.SeverityCritical
					description += " 同源访问只返回了请求中不存在的随机算术结果，且未返回 JSP 源码，已确认 JSP 被服务端执行。"
					evidence = append(evidence, ctx.Evidence("同源访问确认 JSP 无害算术执行", verify, &verifyResponse, map[string]any{"uploaded_path": uploadedPath, "expected": executionExpected, "confirmed_execution": true, "evidence_strength": "L5"}))
				} else if verifyErr == nil && verifyResponse.StatusCode >= 200 && verifyResponse.StatusCode < 300 &&
					tokenWasSent && strings.Contains(verifyResponse.Text(), token) {
					confidenceValue = model.ConfidenceCertain
					severityValue = model.SeverityHigh
					description += " 上传响应给出的同源地址可再次读取唯一 canary，已确认文件实际落地并可访问。"
					evidence = append(evidence, ctx.Evidence("同源读取上传资源命中唯一 canary", verify, &verifyResponse, map[string]any{"uploaded_path": uploadedPath}))
				}
			}
			affected := fmt.Sprintf("body:multipart:%s[%d]", defaultString(file.FieldName, "file"), file.Index)
			severityValue = model.SeverityLow
			findings = append(findings, Finding(meta, fmt.Sprintf("服务端接受危险文件类型 %s", filename), severityValue, confidenceValue,
				affected, description,
				"使用扩展名、MIME 和文件特征白名单；服务端随机重命名；保存到 Web 根目录外，并禁止上传目录脚本执行。",
				evidence,
				"OWASP Unrestricted File Upload"))
		}
	}
	return findings, nil
}

func uploadAccepted(ctx *Context, response model.Response, filename, token string, tokenWasSent bool, expected *regexp.Regexp) (string, bool, bool) {
	expectedChanged := expected != nil && expected.Match(response.Body) && !expected.Match(ctx.Baseline.Body)
	renamedEvidence, renamedAccepted := renamedDangerousUpload(response, ctx.Baseline, filename)
	rejected := uploadRejectionPattern.Match(response.Body)
	statusAccepted := response.StatusCode >= 200 && response.StatusCode < 300
	// Some legacy Servlet/CTP wrappers save the upload and then return a
	// generic 500. A newly returned filename label with the exact tested
	// dangerous suffix is stronger than that wrapper status; authentication,
	// WAF and rate-limit statuses remain excluded.
	if renamedAccepted && response.StatusCode != 401 && response.StatusCode != 403 &&
		response.StatusCode != 406 && response.StatusCode != 429 {
		statusAccepted = true
	}
	accepted := statusAccepted && !rejected &&
		(expectedChanged || renamedAccepted || strings.Contains(response.Text(), filename) ||
			(tokenWasSent && strings.Contains(response.Text(), token)) || uploadedResourcePath(response) != "")
	return renamedEvidence, renamedAccepted, accepted
}

func multipartFieldNameLooksLikeFilename(fieldName string) bool {
	extension := filepath.Ext(strings.TrimSpace(fieldName))
	return multipartFilenameLikePattern.MatchString(extension)
}

var (
	multipartFilenameLikePattern = regexp.MustCompile(`(?i)^\.[a-z0-9]{1,12}$`)
	uploadRejectionPattern       = regexp.MustCompile(`(?is)(UploadFileTypeNot|file\s*type\s*(?:is\s*)?not\s*(?:allowed|supported)|extension\s*(?:is\s*)?not\s*(?:allowed|supported)|文件类型.{0,30}(?:不允许|不支持|错误)|不支持.{0,30}(?:后缀|扩展名|文件类型))`)
)

// renamedDangerousUpload recognizes upload responses that replace the submitted
// name but preserve its dangerous extension, for example
// filename：“202607240001.jspx”. A filename-labelled field must be new relative
// to the baseline; a generic error message mentioning the suffix is not enough.
func renamedDangerousUpload(response, baseline model.Response, submitted string) (string, bool) {
	extension := strings.TrimPrefix(strings.ToLower(filepath.Ext(submitted)), ".")
	if extension == "" {
		return "", false
	}
	match := renamedFilenameEvidence(response.Body, extension)
	if match == "" || renamedFilenameEvidence(baseline.Body, extension) != "" {
		return "", false
	}
	return match, true
}

// renamedFilenameEvidence tolerates legacy JSON-in-string escaping, full-width
// punctuation and CTP text wrappers. It still requires a filename-like label
// close to the exact dangerous extension, so an arbitrary error message that
// merely mentions ".jspx" is not sufficient.
func renamedFilenameEvidence(body []byte, extension string) string {
	extensionPattern := regexp.MustCompile(`(?i)\.` + regexp.QuoteMeta(extension) + `\b`)
	labelPattern := regexp.MustCompile(`(?i)(?:file[\s_-]*name|new[\s_-]*filename|saved[\s_-]*filename|文件名)`)
	for _, location := range extensionPattern.FindAllIndex(body, -1) {
		start := max(0, location[0]-320)
		window := body[start:location[1]]
		labels := labelPattern.FindAllIndex(window, -1)
		if len(labels) == 0 {
			continue
		}
		label := labels[len(labels)-1]
		if location[0]-start-label[1] > 280 {
			continue
		}
		evidenceStart := start + label[0]
		evidenceEnd := min(len(body), location[1]+32)
		return string(body[evidenceStart:evidenceEnd])
	}
	return ""
}

func uploadedResourcePath(response model.Response) string {
	candidates := []string{response.Header("Location")}
	pattern := regexp.MustCompile(`(?i)"(?:url|path|location|downloadUrl)"\s*:\s*"([^"]+)"`)
	if match := pattern.FindStringSubmatch(response.Text()); len(match) == 2 {
		candidates = append(candidates, strings.ReplaceAll(match[1], `\/`, `/`))
	}
	for _, candidate := range candidates {
		parsed, err := url.Parse(strings.TrimSpace(candidate))
		if err != nil || candidate == "" || parsed.IsAbs() || !strings.HasPrefix(parsed.Path, "/") {
			continue
		}
		return parsed.RequestURI()
	}
	return ""
}
