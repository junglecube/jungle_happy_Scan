package plugin

import (
	"strconv"
	"strings"

	"jungle_happy_Scan/internal/model"
)

type JavaExpression struct{}

func (JavaExpression) Meta() model.PluginMeta {
	return StandardMeta("java_expression", "Java 表达式注入", "使用两组随机无害算术表达式检测 SpEL、Thymeleaf、FreeMarker 与 OGNL 求值，不访问类型、不执行命令。", "active", true)
}

func (p JavaExpression) Scan(ctx *Context) ([]model.Finding, error) {
	return scanJavaExpression(ctx, p.Meta())
}

func scanJavaExpression(ctx *Context, meta model.PluginMeta) ([]model.Finding, error) {
	payloads := payloadsForMode(ctx.Rule(meta.ID), ctx.Mode)
	total := len(ctx.Points) * len(payloads) * 2
	done := 0
	ctx.Progress(meta.ID, 0, max(total, 1))
	for _, point := range ctx.Points {
		for _, payload := range payloads {
			var evidence []model.Evidence
			confirmed := true
			for round := 0; round < 2; round++ {
				left, right := expressionOperands(round)
				expected := strconv.Itoa(left * right)
				value := expandPayload(payload.Payload, map[string]string{
					"value": point.Value, "left": strconv.Itoa(left), "right": strconv.Itoa(right), "expected": expected,
				})
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
				evidence = append(evidence, ctx.Evidence("响应出现无害算术求值结果", request, &response, map[string]any{
					"expected": expected, "expression_family": payload.Name, "round": round + 1, "paired_confirmed": round == 1,
				}))
			}
			if confirmed && len(evidence) == 2 {
				return []model.Finding{Finding(meta, "Java 表达式被服务端求值", model.SeverityCritical, model.ConfidenceCertain, point.Label(),
					"两组不同的无害随机算术表达式均返回对应计算结果，结果不在请求原文和基线中。检测不访问 Java 类型、不加载类、不执行命令。",
					"禁止将用户输入作为表达式源码；使用固定表达式、强类型数据绑定和允许字段白名单；升级受影响模板/表达式组件。",
					evidence, "CWE-917")}, nil
			}
		}
	}
	return nil, nil
}

func expressionOperands(round int) (int, int) {
	left, right := commandOperands()
	return 101 + int(left%701) + round, 103 + int(right%503) + round
}
