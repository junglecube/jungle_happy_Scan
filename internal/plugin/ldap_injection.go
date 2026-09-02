package plugin

import (
	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

type LDAPInjection struct{}

func (LDAPInjection) Meta() model.PluginMeta {
	return StandardMeta("ldap_injection", "LDAP 注入", "使用 LDAP 过滤器破坏与真假条件反序复核，检测 Java 目录查询中的未转义输入。", "active", true)
}

func (p LDAPInjection) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	return scanPairedInjection(ctx, meta, func(ctx *Context, point httpraw.InsertionPoint, value string) (*httpraw.Request, error) {
		return ctx.Mutate(point, value)
	}, "LDAP 注入", "结果说明输入可能进入 LDAP 搜索过滤器。",
		"使用标准 LDAP filter encoder 转义输入；固定属性名和过滤器结构；查询账号遵循最小权限。",
		"OWASP WSTG-INPV-06")
}
