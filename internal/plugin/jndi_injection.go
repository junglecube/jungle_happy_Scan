package plugin

import (
	"time"

	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

type JNDIInjection struct{}

func (JNDIInjection) Meta() model.PluginMeta {
	return StandardMeta("jndi_injection", "JNDI/Log4j 回连注入", "向可配置 Header/参数注入唯一 LDAP JNDI 标记；本地监听器只记录 Token，不返回类、不执行命令。", "active", true)
}

func (p JNDIInjection) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	if ctx.Config.CallbackLDAPBaseURL == "" {
		ctx.Progress(meta.ID, 1, 1)
		return nil, nil
	}
	payloads := payloadsForMode(ctx.Rule(meta.ID), ctx.Mode)
	total := 0
	for _, payload := range payloads {
		if payload.Header != "" {
			total++
		} else {
			total += len(ctx.Points)
		}
	}
	ctx.Progress(meta.ID, 0, max(total, 1))
	type probe struct {
		token, rule, affected string
		request               *httpraw.Request
		response              model.Response
	}
	pending := make([]probe, 0, len(payloads))
	done := 0
	for _, payload := range payloads {
		targets := []httpraw.InsertionPoint{{Location: "header", Name: payload.Header}}
		if payload.Header == "" {
			targets = ctx.Points
		}
		for _, target := range targets {
			token, callbackURL := ctx.Callbacks.Register(ctx.Config.CallbackLDAPBaseURL, "jndi")
			value := expandPayload(payload.Payload, map[string]string{"callback": callbackURL, "token": token})
			request := ctx.Request
			affected := target.Label()
			if payload.Header != "" {
				request = request.WithHeader(payload.Header, value)
				affected = "header:" + payload.Header
			} else {
				var err error
				request, err = ctx.Mutate(target, value)
				if err != nil {
					done++
					ctx.Progress(meta.ID, done, total)
					continue
				}
			}
			response, err := ctx.Send(request)
			if err != nil {
				return nil, err
			}
			pending = append(pending, probe{token: token, rule: payload.Name, affected: affected, request: request, response: response})
			done++
			ctx.Progress(meta.ID, done, total)
		}
	}
	tokens := make([]string, 0, len(pending))
	for _, candidate := range pending {
		tokens = append(tokens, candidate.token)
	}
	hits := waitCallbackBatch(ctx.Context, ctx.Callbacks, tokens, 8*time.Second)
	var findings []model.Finding
	for _, candidate := range pending {
		if !hits[candidate.token] {
			continue
		}
		findings = append(findings, Finding(meta, "输入触发服务端 JNDI/LDAP 查找", model.SeverityCritical, model.ConfidenceCertain, candidate.affected,
			"目标对唯一 JNDI 标记发起 LDAP 连接。扫描器只接收 Token 并立即断开，未返回远程类、序列化对象或命令。",
			"升级 Log4j/JDK 及相关日志组件；禁止对不可信输入执行 JNDI lookup；限制应用服务器 LDAP/RMI 出站访问。",
			[]model.Evidence{ctx.Evidence("收到唯一 LDAP/JNDI 回连", candidate.request, &candidate.response, map[string]any{
				"callback": true, "callback_token": candidate.token, "payload_rule": candidate.rule, "evidence_strength": "L5",
			})}, "CVE-2021-44228", "CWE-917"))
	}
	return findings, nil
}
