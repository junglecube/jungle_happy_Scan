package plugin

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/diff"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

const (
	smsThreshold = 5
	smsBatchSize = 30
)

type SMSAbuse struct{}

type smsBatchResult struct {
	request  *httpraw.Request
	response model.Response
	err      error
	success  bool
	value    string
}

func (SMSAbuse) Meta() model.PluginMeta {
	return StandardMeta("sms_abuse", "短信轰炸/喷洒", "对手机号参数同步并发发送 30 次，以一分钟内返回成功超过 5 次判断短信轰炸和多号码喷洒。", "state-changing", true)
}

func (p SMSAbuse) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	rule := ctx.Rule(meta.ID)
	if !smsURLMatches(ctx.Request, rule.URLKeywords) {
		ctx.Progress(meta.ID, 0, 0)
		return nil, nil
	}
	patterns := compileDetectionPatterns(rule.Patterns)
	var points []httpraw.InsertionPoint
	for _, point := range ctx.Points {
		if semanticName(point.Name, rule.ParameterNames) {
			points = append(points, point)
		}
	}
	sprayRules := payloadsByKind(payloadsForMode(rule, ctx.Mode), "spray_number")
	totalPerPoint := smsBatchSize * 2
	total := len(points) * totalPerPoint
	ctx.Progress(meta.ID, 0, max(total, 1))
	var completed atomic.Int64
	progress := func() {
		done := int(completed.Add(1))
		ctx.Progress(meta.ID, min(done, total), max(total, 1))
	}
	var findings []model.Finding
	for _, point := range points {
		bombRequests := make([]*httpraw.Request, 0, smsBatchSize)
		for range smsBatchSize {
			request, err := ctx.Mutate(point, point.Value)
			if err == nil {
				bombRequests = append(bombRequests, request)
			}
		}
		started := time.Now()
		bombResults := sendSMSBatch(ctx, bombRequests, nil, patterns, progress)
		elapsed := time.Since(started)
		bombSuccess := successfulSMSResults(bombResults)
		if len(bombSuccess) > smsThreshold && elapsed <= time.Minute {
			findings = append(findings, Finding(meta, "短信接口缺少单号码发送频率限制", model.SeverityHigh, model.ConfidenceFirm, point.Label(),
				"扫描器以同步屏障同时启动 30 个相同号码请求，其中返回成功超过 5 次，且整个批次在一分钟内完成。该结论依据响应语义，不声称真实短信一定到达。",
				"在服务端按手机号、账号、设备、来源 IP 和业务场景实施组合限流；使用原子计数器或集中式限流，超过阈值时返回明确拒绝并避免进入短信网关。",
				smsEvidence(ctx, bombSuccess, "同号码高并发批次", map[string]any{
					"requests": len(bombRequests), "successful_responses": len(bombSuccess),
					"threshold": smsThreshold, "window_ms": elapsed.Milliseconds(), "concurrent": true,
				}), "CWE-799"))
		}

		sprayRequests, sprayValues := smsSprayRequests(ctx, point, sprayRules)
		started = time.Now()
		sprayResults := sendSMSBatch(ctx, sprayRequests, sprayValues, patterns, progress)
		elapsed = time.Since(started)
		spraySuccess := successfulSMSResults(sprayResults)
		unique := make(map[string]bool)
		for _, result := range spraySuccess {
			unique[result.value] = true
		}
		if len(unique) > smsThreshold && elapsed <= time.Minute {
			findings = append(findings, Finding(meta, "短信接口缺少多号码喷洒限制", model.SeverityHigh, model.ConfidenceFirm, point.Label(),
				"扫描器高并发发送多个不同测试号码，一分钟内超过 5 个不同号码获得发送成功响应。该结论仅依据接口响应，不声称真实短信一定到达。",
				"除单号码限流外，对账号、设备、IP、机构及业务场景设置滑动窗口总量；识别短时间多号码扩散，并在短信网关前统一阻断。",
				smsEvidence(ctx, spraySuccess, "多号码高并发喷洒批次", map[string]any{
					"requests": len(sprayRequests), "successful_responses": len(spraySuccess),
					"unique_successful_numbers": len(unique), "threshold": smsThreshold,
					"window_ms": elapsed.Milliseconds(), "concurrent": true,
				}), "CWE-799"))
		}
	}
	ctx.Progress(meta.ID, max(int(completed.Load()), total), max(total, 1))
	return findings, nil
}

func smsURLMatches(request *httpraw.Request, keywords []string) bool {
	if request == nil {
		return false
	}
	target := strings.ToLower(request.Target)
	for _, keyword := range keywords {
		keyword = strings.ToLower(strings.TrimSpace(keyword))
		if keyword != "" && strings.Contains(target, keyword) {
			return true
		}
	}
	return false
}

func sendSMSBatch(ctx *Context, requests []*httpraw.Request, values []string, patterns []compiledPattern, progress func()) []smsBatchResult {
	results := make([]smsBatchResult, len(requests))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for index, request := range requests {
		wg.Add(1)
		go func(index int, request *httpraw.Request) {
			defer wg.Done()
			select {
			case <-start:
			case <-ctx.Context.Done():
				results[index].err = ctx.Context.Err()
				progress()
				return
			}
			response, err := ctx.Send(request)
			value := ""
			if index < len(values) {
				value = values[index]
			}
			results[index] = smsBatchResult{
				request: request, response: response, err: err, value: value,
				success: err == nil && smsResponseSuccess(response, ctx, patterns),
			}
			progress()
		}(index, request)
	}
	close(start)
	wg.Wait()
	return results
}

func smsResponseSuccess(response model.Response, ctx *Context, patterns []compiledPattern) bool {
	if response.StatusCode < 200 || response.StatusCode >= 300 || diff.LikelyAuthDenied(response, ctx.Config) {
		return false
	}
	if smsStructuredSuccess(response.Body) {
		return true
	}
	if len(patterns) > 0 && firstPatternRule(patterns, response.Body).name != "" {
		return true
	}
	return diff.LikelySuccess(response, ctx.Config)
}

func smsStructuredSuccess(body []byte) bool {
	var value any
	if json.Unmarshal(body, &value) != nil {
		return false
	}
	success, failure := walkSMSOutcome(value)
	return success && !failure
}

func walkSMSOutcome(value any) (success, failure bool) {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			switch strings.ToLower(strings.TrimSpace(key)) {
			case "code", "status", "statuscode", "resultcode", "retcode":
				normalized := strings.TrimSpace(fmt.Sprint(item))
				if normalized == "0" || normalized == "200" || normalized == "000000" {
					success = true
				} else if number, ok := item.(float64); ok && number >= 400 {
					failure = true
				}
			case "success", "successful":
				if flag, ok := item.(bool); ok {
					if flag {
						success = true
					} else {
						failure = true
					}
				}
			case "msg", "message", "resultmsg", "resultmessage":
				message := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(fmt.Sprint(item)), " ", ""))
				if strings.Contains(message, "失败") || strings.Contains(message, "频繁") || strings.Contains(message, "稍后") || strings.Contains(message, "错误") || strings.Contains(message, "invalid") || strings.Contains(message, "toomany") || strings.Contains(message, "limit") {
					failure = true
				}
				if strings.Contains(message, "发送成功") || strings.Contains(message, "下发成功") {
					success = true
				}
			}
			childSuccess, childFailure := walkSMSOutcome(item)
			success, failure = success || childSuccess, failure || childFailure
		}
	case []any:
		for _, item := range typed {
			childSuccess, childFailure := walkSMSOutcome(item)
			success, failure = success || childSuccess, failure || childFailure
		}
	}
	return success, failure
}

func successfulSMSResults(results []smsBatchResult) []smsBatchResult {
	successful := make([]smsBatchResult, 0, len(results))
	for _, result := range results {
		if result.success {
			successful = append(successful, result)
		}
	}
	return successful
}

func smsSprayRequests(ctx *Context, point httpraw.InsertionPoint, rules []config.PayloadRule) ([]*httpraw.Request, []string) {
	original := strings.TrimSpace(point.Value)
	prefix := original
	if len(original) >= 4 {
		prefix = original[:len(original)-4]
	}
	seen := make(map[string]bool)
	var requests []*httpraw.Request
	var values []string
	for _, rule := range rules {
		if len(requests) >= smsBatchSize {
			break
		}
		value := expandPayload(rule.Payload, map[string]string{"value": original, "prefix": prefix})
		if value == "" || value == original || seen[value] {
			continue
		}
		request, err := ctx.Mutate(point, value)
		if err != nil {
			continue
		}
		seen[value] = true
		requests = append(requests, request)
		values = append(values, value)
	}
	for index := 0; len(requests) < smsBatchSize && index < 100; index++ {
		value := fmt.Sprintf("%s%04d", prefix, 7300+index)
		if value == original || seen[value] {
			continue
		}
		request, err := ctx.Mutate(point, value)
		if err != nil {
			continue
		}
		seen[value] = true
		requests = append(requests, request)
		values = append(values, value)
	}
	return requests, values
}

func smsEvidence(ctx *Context, results []smsBatchResult, summary string, metrics map[string]any) []model.Evidence {
	if len(results) == 0 {
		return nil
	}
	evidence := []model.Evidence{ctx.Evidence(summary+"：首个成功响应", results[0].request, &results[0].response, metrics)}
	if len(results) > 1 {
		last := results[len(results)-1]
		evidence = append(evidence, ctx.Evidence(summary+"：末个成功响应", last.request, &last.response, map[string]any{
			"successful_index": len(results), "phone_value": last.value,
		}))
	}
	return evidence
}
