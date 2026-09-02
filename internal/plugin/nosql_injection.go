package plugin

import (
	"encoding/json"
	"fmt"

	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

type NoSQLInjection struct{}

func (NoSQLInjection) Meta() model.PluginMeta {
	return StandardMeta("nosql_injection", "NoSQL 注入", "针对 MongoDB/文档数据库执行结构化操作符真假差分和错误特征重复确认。", "active", true)
}

func (p NoSQLInjection) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	return scanPairedInjection(ctx, meta, func(ctx *Context, point httpraw.InsertionPoint, value string) (*httpraw.Request, error) {
		if point.Location == "query" || point.Location == "form" {
			var operator map[string]any
			if err := json.Unmarshal([]byte(value), &operator); err == nil && len(operator) == 1 {
				for name, operand := range operator {
					operandText := ""
					if operand != nil {
						operandText = fmt.Sprint(operand)
					}
					return httpraw.MutateParameterNameValue(ctx.Request, point, point.Name+"["+name+"]", operandText)
				}
			}
		}
		return httpraw.MutateJSONRaw(ctx.Request, point, value)
	}, "NoSQL 注入", "检测不读取业务数据，仅确认用户输入是否被解释为 NoSQL 查询操作符。",
		"禁止将请求 JSON 直接作为查询对象；按字段构造查询并拒绝以 $ 开头的键；启用严格 Schema 和类型校验。",
		"OWASP WSTG-INPV-05")
}
