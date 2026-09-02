package plugin

import (
	"net/http"
	"strings"

	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

type SpringActuator struct{}

func (SpringActuator) Meta() model.PluginMeta {
	return StandardMeta("spring_actuator", "Spring Boot Actuator 暴露", "探测同源 Actuator/management 的 health、env、beans、configprops、mappings、loggers 与 threaddump；不下载 heapdump。", "adjacent-path", true)
}

func (p SpringActuator) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	configuredPaths := ctx.Rule(meta.ID).Paths
	paths := contextualPaths(ctx.Request, configuredPaths)
	ctx.Progress(meta.ID, 0, len(paths))
	var findings []model.Finding
	for index, path := range paths {
		request := ctx.Request.ReplaceTarget(path)
		request.Method = http.MethodGet
		request = request.WithBody(nil).WithoutHeaders("Content-Type", "Content-Length")
		request, _ = httpraw.RemoveSessions(request, httpraw.EffectiveSessionIdentifiers(request, ctx.Config.SessionIdentifiers))
		response, err := ctx.Send(request)
		if err != nil {
			return findings, err
		}
		ctx.Progress(meta.ID, index+1, len(paths))
		text := strings.ToLower(response.Text())
		kind := javaManagementSignature(path, text)
		exposed := response.StatusCode == 200 && kind != ""
		if !exposed {
			continue
		}
		severity := model.SeverityMedium
		if strings.Contains(path, "/env") || strings.Contains(path, "/configprops") || strings.Contains(path, "/mappings") || strings.Contains(path, "/loggers") || strings.Contains(path, "/threaddump") {
			severity = model.SeverityHigh
		}
		title := "Spring Boot " + path + " 可直接访问"
		if kind != "actuator" {
			title = "Java 管理/调试端点 " + kind + " 可直接访问"
			severity = model.SeverityHigh
		}
		findings = append(findings, Finding(meta, title, severity, model.ConfidenceCertain, path,
			"删除配置的会话标识后，同源管理端点仍返回明确的 "+kind+" 结构特征，可能暴露配置、运行状态或管理能力。",
			"只暴露必要端点；隔离管理端口；为管理端点配置强认证并隐藏敏感值。",
			[]model.Evidence{ctx.Evidence("响应包含 Actuator 结构特征", request, &response, map[string]any{"path": path})}))
	}
	return findings, nil
}

func actuatorSignature(text string) bool {
	return strings.Contains(text, `"_links"`) || strings.Contains(text, `"propertysources"`) ||
		strings.Contains(text, `"beans"`) || strings.Contains(text, `"contexts"`) ||
		strings.Contains(text, `"handlermethods"`) || strings.Contains(text, `"configuredlevel"`) ||
		strings.Contains(text, `"threads"`) && strings.Contains(text, `"threadname"`) ||
		strings.Contains(text, `"status"`) && (strings.Contains(text, `"up"`) || strings.Contains(text, `"down"`))
}

func javaManagementSignature(targetPath, text string) string {
	if actuatorSignature(text) {
		return "actuator"
	}
	if strings.Contains(text, "druid monitor") || strings.Contains(text, "druid stat index") || strings.Contains(text, "com.alibaba.druid") {
		return "Druid Monitor"
	}
	if strings.Contains(text, "h2 console") && (strings.Contains(text, "jdbc url") || strings.Contains(text, "org.h2")) {
		return "H2 Console"
	}
	if strings.Contains(strings.ToLower(targetPath), "jolokia") && strings.Contains(text, `"request"`) && strings.Contains(text, `"value"`) && strings.Contains(text, `"status"`) {
		return "Jolokia"
	}
	if strings.Contains(text, "spring boot admin") || strings.Contains(text, "spring-boot-admin") {
		return "Spring Boot Admin"
	}
	return ""
}
