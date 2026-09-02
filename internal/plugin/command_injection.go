package plugin

import (
	"strconv"
	"strings"
	"time"

	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

type CommandInjection struct{}

func (CommandInjection) Meta() model.PluginMeta {
	return StandardMeta("command_injection", "OS 命令注入", "使用多Shell上下文的无害算术输出canary确认命令执行。", "active", true)
}

func (p CommandInjection) Scan(ctx *Context) ([]model.Finding, error) {
	return scanCommandInjection(ctx, p.Meta())
}

func scanCommandInjection(ctx *Context, meta model.PluginMeta) ([]model.Finding, error) {
	rule := ctx.Rule(meta.ID)
	parameterNames := append(append([]string(nil), rule.ParameterNames...), ctx.Config.CommandParameterNames...)
	filtered := make([]httpraw.InsertionPoint, 0, len(ctx.Points))
	for _, point := range ctx.Points {
		if semanticName(point.Name, parameterNames) {
			filtered = append(filtered, point)
		}
	}
	payloads := payloadsForMode(rule, ctx.Mode)
	outputPayloads := payloadsByKind(payloads, "output")
	outputPayloads = append(outputPayloads, payloadsByKind(payloads, "direct_output")...)
	callbackPayloads := payloadsByKind(payloads, "callback")
	delayPairs := pairPayloads(payloads, "delay", "control")
	checksPerPoint := len(outputPayloads)*3 + len(callbackPayloads) + len(delayPairs)*2
	total := len(filtered) * checksPerPoint
	done := 0
	ctx.Progress(meta.ID, 0, max(total, 1))
	type callbackProbe struct {
		token, rule, affected string
		request               *httpraw.Request
		response              model.Response
	}
	pending := make([]callbackProbe, 0)
	var findings []model.Finding
	for _, point := range filtered {
		for _, payload := range outputPayloads {
			if payload.Kind == "direct_output" && !directCommandParameter(point.Name) {
				done += 3
				ctx.Progress(meta.ID, done, total)
				continue
			}
			left, right := commandOperands()
			sum := left + right
			replacements := map[string]string{
				"value": point.Value, "left": strconv.FormatInt(left, 10),
				"right": strconv.FormatInt(right, 10), "sum": strconv.FormatInt(sum, 10),
			}
			value := expandPayload(payload.Payload, replacements)
			expected := expandPayload(payload.Expected, replacements)
			if expected == "" || strings.Contains(value, expected) {
				done += 3
				ctx.Progress(meta.ID, done, total)
				continue
			}
			request, err := ctx.Mutate(point, value)
			if err != nil {
				done += 3
				continue
			}
			first, err := ctx.Send(request)
			if err != nil {
				return findings, err
			}
			done++
			ctx.Progress(meta.ID, done, total)
			if !strings.Contains(first.Text(), expected) || strings.Contains(ctx.Baseline.Text(), expected) {
				done += 2
				ctx.Progress(meta.ID, done, total)
				continue
			}
			control, err := ctx.Send(ctx.Request)
			if err != nil {
				return findings, err
			}
			done++
			if strings.Contains(control.Text(), expected) {
				done++
				ctx.Progress(meta.ID, done, total)
				continue
			}
			second, err := ctx.Send(request)
			if err != nil {
				return findings, err
			}
			done++
			ctx.Progress(meta.ID, done, total)
			if strings.Contains(second.Text(), expected) {
				findings = append(findings, Finding(meta, "输入进入系统命令执行", model.SeverityCritical, model.ConfidenceCertain, point.Label(),
					"两次变异响应均出现由服务端算术求值得到的随机结果，原始请求和恢复响应中不存在该结果。即使应用完整反射 Payload，也不会满足此条件。",
					"避免调用 shell；使用参数数组形式的安全 API；对不可避免的参数实施严格白名单。",
					[]model.Evidence{
						ctx.Evidence("第一次响应出现请求中不存在的计算结果", request, &first, map[string]any{"expected": expected, "left": left, "right": right, "payload_rule": payload.Name, "confirmed_execution": true, "evidence_strength": "L5"}),
						ctx.Evidence("恢复原请求后计算结果消失", ctx.Request, &control, nil),
						ctx.Evidence("第二次重复确认计算结果", request, &second, map[string]any{"expected": expected, "confirmed_execution": true, "evidence_strength": "L5"}),
					}, "OWASP WSTG-INPV-12"))
			}
		}
		for _, payload := range callbackPayloads {
			if ctx.Config.CallbackBaseURL == "" {
				done++
				ctx.Progress(meta.ID, done, total)
				continue
			}
			token, callbackURL := ctx.Callbacks.Register(ctx.Config.CallbackBaseURL, "command")
			value := expandPayload(payload.Payload, map[string]string{"value": point.Value, "callback": callbackURL, "token": token})
			request, err := ctx.Mutate(point, value)
			if err != nil {
				done++
				ctx.Progress(meta.ID, done, total)
				continue
			}
			response, err := ctx.Send(request)
			if err != nil {
				return findings, err
			}
			done++
			ctx.Progress(meta.ID, done, total)
			pending = append(pending, callbackProbe{token: token, rule: payload.Name, affected: point.Label(), request: request, response: response})
		}
		for _, pair := range delayPairs {
			if strings.HasPrefix(pair.group, "groovy-") && !scriptExpressionParameter(point.Name) {
				done += 2
				ctx.Progress(meta.ID, done, total)
				continue
			}
			delayValue := expandPayload(pair.left.Payload, map[string]string{"value": point.Value})
			controlValue := expandPayload(pair.right.Payload, map[string]string{"value": point.Value})
			delayRequest, err1 := ctx.Mutate(point, delayValue)
			controlRequest, err2 := ctx.Mutate(point, controlValue)
			if err1 != nil || err2 != nil {
				done += 2
				continue
			}
			delayed, err := ctx.Send(delayRequest)
			if err != nil {
				return findings, err
			}
			done++
			ctx.Progress(meta.ID, done, total)
			control, err := ctx.Send(controlRequest)
			if err != nil {
				return findings, err
			}
			done++
			ctx.Progress(meta.ID, done, total)
			delta := delayed.Elapsed - control.Elapsed
			if delta >= 1700*time.Millisecond && control.Elapsed*2 < delayed.Elapsed {
				findings = append(findings, Finding(meta, "输入疑似进入系统命令执行", model.SeverityCritical, model.ConfidenceFirm, point.Label(),
					"配置的延时 payload 相对控制请求产生稳定显著延迟。",
					"避免调用 shell；使用参数数组形式的安全 API；对不可避免的参数实施严格白名单。",
					[]model.Evidence{ctx.Evidence("延时与控制请求形成差异", delayRequest, &delayed, map[string]any{
						"delayed_ms": delayed.Elapsed.Milliseconds(), "control_ms": control.Elapsed.Milliseconds(), "delta_ms": delta.Milliseconds(), "payload_rule": pair.left.Name,
					})}, "OWASP WSTG-INPV-12"))
			}
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
		findings = append(findings, Finding(meta, "系统命令产生离线 HTTP 回连", model.SeverityCritical, model.ConfidenceCertain, candidate.affected,
			"扫描器收到由目标服务器 curl 触发的唯一一次性回连 Token，证明输入进入了系统命令执行流程；测试未读取服务器文件或执行业务操作。",
			"避免调用 shell；使用参数数组形式的安全 API；对不可避免的参数实施严格白名单，并限制应用服务器出站网络。",
			[]model.Evidence{ctx.Evidence("收到唯一命令执行回连", candidate.request, &candidate.response, map[string]any{"callback": true, "callback_token": candidate.token, "payload_rule": candidate.rule, "evidence_strength": "L5"})},
			"OWASP WSTG-INPV-12"))
	}
	return findings, nil
}

func directCommandParameter(name string) bool {
	name = strings.ToLower(strings.NewReplacer("_", "", "-", "", ".", "").Replace(strings.TrimSpace(name)))
	for _, candidate := range []string{"cmd", "command", "exec", "execute", "executable", "program", "process", "processbuilder"} {
		if name == candidate || strings.HasSuffix(name, candidate) {
			return true
		}
	}
	return false
}

func scriptExpressionParameter(name string) bool {
	name = strings.ToLower(strings.NewReplacer("_", "", "-", "", ".", "").Replace(strings.TrimSpace(name)))
	for _, candidate := range []string{"cmd", "command", "exec", "execute", "script", "code", "expression", "groovy", "engine"} {
		if name == candidate || strings.HasSuffix(name, candidate) {
			return true
		}
	}
	return false
}

func commandOperands() (int64, int64) {
	raw := strings.TrimPrefix(randomID(""), "_")
	value, _ := strconv.ParseInt(raw[:12], 16, 64)
	left := int64(100_000) + value%700_000
	right := int64(100_000) + (value/97)%700_000
	return left, right
}

func payloadsByKind(payloads []config.PayloadRule, kind string) []config.PayloadRule {
	result := make([]config.PayloadRule, 0)
	for _, payload := range payloads {
		if payload.Kind == kind {
			result = append(result, payload)
		}
	}
	return result
}
