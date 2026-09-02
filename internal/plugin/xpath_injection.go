package plugin

import (
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

type XPathInjection struct{}

func (XPathInjection) Meta() model.PluginMeta {
	return StandardMeta("xpath_injection", "XPath 注入", "使用 XPath 语法错误和真假表达式双轮差分确认 XML 查询输入是否可控。", "active", true)
}

func (p XPathInjection) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	return scanPairedInjection(ctx, meta, func(ctx *Context, point httpraw.InsertionPoint, value string) (*httpraw.Request, error) {
		return ctx.Mutate(point, value)
	}, "XPath 注入", "结果说明输入可能被拼接进 XPath 表达式。",
		"使用变量绑定或固定查询模板；对节点名使用白名单；不要通过字符串拼接构造 XPath。",
		"OWASP WSTG-INPV-09")
}
