package plugin

import (
	"fmt"
	"strings"

	"jungle_happy_Scan/internal/model"
)

type SSTI struct{}

func (SSTI) Meta() model.PluginMeta {
	return StandardMeta("ssti", "服务端模板注入", "使用无害算术表达式判断模板引擎是否执行输入。", "active", true)
}

func (p SSTI) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	expressions := payloadsForMode(ctx.Rule(meta.ID), ctx.Mode)
	total := len(ctx.Points) * len(expressions) * 2
	done := 0
	ctx.Progress(meta.ID, 0, max(total, 1))
	for _, point := range ctx.Points {
		for _, expression := range expressions {
			var evidence []model.Evidence
			confirmed := true
			for round := 0; round < 2; round++ {
				left, right := expressionOperands(round)
				expected := fmt.Sprint(left * right)
				value := randomizedTemplateExpression(expression.Payload, left, right)
				request, err := ctx.Mutate(point, value)
				if err != nil {
					confirmed = false
					continue
				}
				response, err := ctx.Send(request)
				if err != nil {
					return nil, err
				}
				done++
				ctx.Progress(meta.ID, done, total)
				if strings.Contains(value, expected) || strings.Contains(ctx.Baseline.Text(), expected) || !strings.Contains(response.Text(), expected) {
					confirmed = false
					continue
				}
				evidence = append(evidence, ctx.Evidence("随机算术模板表达式返回确定计算结果", request, &response, map[string]any{"payload": value, "expected": expected, "payload_rule": expression.Name, "round": round + 1, "paired_confirmed": round == 1}))
			}
			if confirmed && len(evidence) == 2 {
				return []model.Finding{Finding(meta, "模板表达式被服务端求值", model.SeverityCritical, model.ConfidenceCertain, point.Label(),
					"两组不同的无害随机算术表达式均返回各自计算结果，且结果不在请求原文和基线中。",
					"不要把用户输入作为模板源码；使用固定模板和严格的数据绑定。", evidence, "OWASP WSTG-INPV-18")}, nil
			}
		}
	}
	return nil, nil
}

func randomizedTemplateExpression(template string, left, right int) string {
	inner := fmt.Sprintf("%d*%d", left, right)
	trimmed := strings.TrimSpace(template)
	switch {
	case strings.HasPrefix(trimmed, "{{"):
		return "{{" + inner + "}}"
	case strings.HasPrefix(trimmed, "${"):
		return "${" + inner + "}"
	case strings.HasPrefix(trimmed, "#{"):
		return "#{" + inner + "}"
	case strings.HasPrefix(trimmed, "%{"):
		return "%{" + inner + "}"
	case strings.HasPrefix(trimmed, "*{"):
		return "*{" + inner + "}"
	default:
		return "${" + inner + "}"
	}
}
