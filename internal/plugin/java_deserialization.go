package plugin

import (
	"encoding/base64"
	"strings"

	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

type JavaDeserialization struct{}

func (JavaDeserialization) Meta() model.PluginMeta {
	return StandardMeta("java_deserialization", "Java 不安全反序列化入口", "Standard 仅用畸形对象流确认反序列化入口；Deep 支持管理员配置的无副作用输出 canary，不内置破坏性 gadget。", "active", true)
}

func (p JavaDeserialization) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	rule := ctx.Rule(meta.ID)
	payloads := payloadsForMode(rule, ctx.Mode)
	patterns := compileDetectionPatterns(rule.Patterns)
	baselinePatterns := matchingPatternNames(patterns, ctx.Baselines)
	points := deserializationPoints(ctx, rule.ParameterNames)
	total := len(points) * len(payloads) * 2
	ctx.Progress(meta.ID, 0, max(total, 1))
	done := 0
	var findings []model.Finding
	for _, point := range points {
		for _, payload := range payloads {
			token := randomID("jhs")
			value := expandPayload(payload.Payload, map[string]string{"token": token, "value": point.Value})
			request, err := deserializationRequest(ctx, point, value)
			if err != nil {
				done += 2
				continue
			}
			first, err := ctx.Send(request)
			if err != nil {
				return findings, err
			}
			done++
			if payload.Kind == "command_canary" {
				expected := expandPayload(payload.Expected, map[string]string{"token": token})
				if expected == "" || !strings.Contains(first.Text(), expected) {
					done++
					continue
				}
			} else {
				match := firstPatternRule(patterns, first.Body)
				if match.name == "" || baselinePatterns[match.name] {
					done++
					continue
				}
			}
			second, err := ctx.Send(request)
			if err != nil {
				return findings, err
			}
			done++
			ctx.Progress(meta.ID, done, total)
			if payload.Kind == "command_canary" {
				expected := expandPayload(payload.Expected, map[string]string{"token": token})
				if !strings.Contains(second.Text(), expected) {
					continue
				}
				findings = append(findings, Finding(meta, "反序列化命令输出 canary 被执行", model.SeverityCritical, model.ConfidenceCertain, point.Label(),
					"管理员配置的 Deep canary 两次返回预期随机标记，说明反序列化链可执行进程命令。",
					"删除原生对象反序列化入口；采用安全数据格式和允许类型清单；隔离反序列化进程权限。",
					[]model.Evidence{
						ctx.Evidence("第一次返回随机命令输出 canary", request, &first, map[string]any{"payload_rule": payload.Name}),
						ctx.Evidence("第二次重复返回随机命令输出 canary", request, &second, nil),
					}, "CWE-502"))
				break
			}
			matchOne := firstPatternRule(patterns, first.Body)
			matchTwo := firstPatternRule(patterns, second.Body)
			if matchOne.name == "" || matchTwo.name != matchOne.name {
				continue
			}
			findings = append(findings, Finding(meta, "检测到 Java 反序列化处理入口", model.SeverityInfo, model.ConfidenceFirm, point.Label(),
				"两次畸形对象流均触发"+matchOne.name+"，原始响应不存在该异常。该证据只确认反序列化入口，不证明过滤器可绕过、存在 gadget 或能够执行代码。插件未执行命令。",
				"禁止反序列化不可信数据；迁移到 JSON/Protobuf；必须保留时使用 JEP 290 ObjectInputFilter 和严格类型白名单。",
				[]model.Evidence{
					ctx.Evidence("第一次畸形对象流触发 "+matchOne.name, request, &first, map[string]any{"payload_rule": payload.Name}),
					ctx.Evidence("第二次畸形对象流重复触发", request, &second, nil),
				}, "CWE-502"))
			break
		}
	}
	ctx.Progress(meta.ID, max(done, total), max(total, 1))
	return findings, nil
}

func deserializationPoints(ctx *Context, configured []string) []httpraw.InsertionPoint {
	if len(configured) == 0 {
		configured = []string{"data", "payload", "object", "serialized", "token", "state"}
	}
	var result []httpraw.InsertionPoint
	for _, point := range ctx.Points {
		value := strings.TrimSpace(point.Value)
		if looksSerialized(value) || semanticName(point.Name, configured) {
			result = append(result, point)
		}
	}
	contentType := ctx.Request.ContentType()
	if len(result) == 0 && (strings.Contains(contentType, "java-serialized") || strings.Contains(contentType, "x-hessian")) {
		result = append(result, httpraw.InsertionPoint{Location: "raw-body", Name: "body", Path: "body", Value: string(ctx.Request.Body), ValueType: "string"})
	}
	return result
}

func looksSerialized(value string) bool {
	if strings.HasPrefix(value, "rO0AB") || strings.HasPrefix(value, "H4sI") || strings.Contains(value, "!!java/") {
		return true
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(decoded) >= 4 && decoded[0] == 0xac && decoded[1] == 0xed
}

func deserializationRequest(ctx *Context, point httpraw.InsertionPoint, value string) (*httpraw.Request, error) {
	if point.Location == "raw-body" {
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err == nil {
			return ctx.Request.WithBody(decoded), nil
		}
		return ctx.Request.WithBody([]byte(value)), nil
	}
	return ctx.Mutate(point, value)
}
