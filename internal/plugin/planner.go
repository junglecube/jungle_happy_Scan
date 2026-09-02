package plugin

import (
	"strings"

	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/httpraw"
)

type ExecutionPlan struct {
	Plugin            Plugin
	Applicable        bool
	Reason            string
	PointsTotal       int
	EstimatedRequests int
	Budget            int
	Priority          int
}

func BuildExecutionPlans(selected []Plugin, request *httpraw.Request, points []httpraw.InsertionPoint, mode string, cfg config.Config, available int) []ExecutionPlan {
	plans := make([]ExecutionPlan, 0, len(selected))
	totalEstimated := 0
	for _, item := range selected {
		meta := item.Meta()
		applicable, reason := pluginApplicable(meta.ID, request, points, cfg)
		estimated := estimateRequests(meta.ID, request, points, mode, cfg)
		pointCount := estimatedPointCount(meta.ID, points, cfg)
		if !applicable {
			estimated = 0
			pointCount = 0
		}
		priority := pluginPriority(meta.ID)
		plans = append(plans, ExecutionPlan{
			Plugin: item, Applicable: applicable, Reason: reason, PointsTotal: pointCount,
			EstimatedRequests: estimated, Priority: priority,
		})
		totalEstimated += estimated
	}
	if available < 0 {
		available = 0
	}
	if totalEstimated <= available {
		for index := range plans {
			plans[index].Budget = plans[index].EstimatedRequests
		}
		return plans
	}

	// Give every applicable plugin a small deterministic floor first, then
	// distribute the remaining budget proportionally by estimate and priority.
	remaining := available
	for index := range plans {
		if !plans[index].Applicable || plans[index].EstimatedRequests == 0 {
			continue
		}
		quantum := planBudgetQuantum(plans[index].Plugin.Meta().ID)
		floor := min(plans[index].EstimatedRequests, max(quantum, plans[index].Priority))
		if floor%quantum != 0 {
			floor -= floor % quantum
		}
		if remaining < floor {
			continue
		}
		plans[index].Budget = min(floor, remaining)
		remaining -= plans[index].Budget
		if remaining == 0 {
			return plans
		}
	}
	for remaining > 0 {
		best := -1
		bestNeed := -1
		for index := range plans {
			need := plans[index].EstimatedRequests - plans[index].Budget
			if need <= 0 {
				continue
			}
			weighted := need * plans[index].Priority
			if weighted > bestNeed {
				best, bestNeed = index, weighted
			}
		}
		if best < 0 {
			break
		}
		quantum := planBudgetQuantum(plans[best].Plugin.Meta().ID)
		chunk := min(remaining, max(quantum, min(8, plans[best].EstimatedRequests-plans[best].Budget)))
		chunk -= chunk % quantum
		if chunk == 0 {
			// This plan cannot consume the remaining fragment without splitting
			// an atomic SQL A-B-B-A cohort. Look for a one-request plan instead.
			best = -1
			for index := range plans {
				if planBudgetQuantum(plans[index].Plugin.Meta().ID) == 1 &&
					plans[index].EstimatedRequests > plans[index].Budget {
					best = index
					break
				}
			}
			if best < 0 {
				break
			}
			chunk = min(remaining, min(8, plans[best].EstimatedRequests-plans[best].Budget))
		}
		plans[best].Budget += chunk
		remaining -= chunk
	}
	return plans
}

func pluginApplicable(id string, request *httpraw.Request, points []httpraw.InsertionPoint, cfg config.Config) (bool, string) {
	contentType := request.ContentType()
	body := strings.ToLower(string(request.Body))
	target := strings.ToLower(request.Target)
	hasPoints := len(points) > 0
	hasNamed := func(names []string) bool {
		for _, point := range points {
			if semanticName(point.Name, names) {
				return true
			}
		}
		return false
	}
	switch id {
	case "xxe", "xxe_extended":
		if !strings.Contains(contentType, "xml") && !strings.HasPrefix(strings.TrimSpace(body), "<") {
			return false, "请求体不是 XML"
		}
	case "file_upload", "file_upload_execution":
		if !strings.Contains(contentType, "multipart/form-data") {
			return false, "请求不是 multipart 文件上传"
		}
		if _, ok := request.FirstMultipartFile(); !ok {
			return false, "multipart 中没有文件字段"
		}
	case "mass_assignment", "mass_assignment_extended":
		if request.Method != "POST" && request.Method != "PUT" && request.Method != "PATCH" {
			return false, "不是可绑定对象的状态变更请求"
		}
	case "json_polymorphic":
		if !strings.Contains(contentType, "json") ||
			(!strings.HasPrefix(strings.TrimSpace(body), "{") && !strings.HasPrefix(strings.TrimSpace(body), "[")) {
			return false, "请求体不是 JSON 对象或数组"
		}
	case "mybatis_dynamic_sql":
		if len(myBatisFragmentPoints(points, cfg.PluginRules[id].ParameterNames)) == 0 {
			return false, "没有排序列、字段名、表名等动态 SQL 候选参数"
		}
	case "sqli_order_by":
		if len(namedSQLContextPoints(points, cfg.PluginRules[id].ParameterNames)) == 0 {
			return false, "没有 ORDER BY 字段或方向候选参数"
		}
	case "sqli_limit":
		if len(namedSQLContextPoints(points, cfg.PluginRules[id].ParameterNames)) == 0 {
			return false, "没有 LIMIT/OFFSET 或分页候选参数"
		}
	case "path_normalization":
		if len(httpraw.SessionPoints(request, cfg.SessionIdentifiers)) == 0 {
			return false, "请求中没有可识别会话"
		}
	case "parameter_confusion":
		hasDuplicateCandidate := false
		for _, point := range points {
			if point.Location == "query" || point.Location == "form" {
				hasDuplicateCandidate = true
				break
			}
		}
		if !hasDuplicateCandidate && len(httpraw.SessionPoints(request, cfg.SessionIdentifiers)) == 0 {
			return false, "没有可重复的参数或会话凭据"
		}
	case "graphql_security", "graphql_alias_abuse":
		if !strings.Contains(target, "graphql") && !strings.Contains(body, `"query"`) {
			return false, "未识别为 GraphQL 请求"
		}
	case "java_deserialization":
		if !strings.Contains(contentType, "serialized") && !strings.Contains(contentType, "hessian") &&
			!hasNamed(cfg.PluginRules[id].ParameterNames) {
			return false, "未发现序列化内容类型或候选字段"
		}
	case "jwt_active":
		found := false
		for _, header := range request.Headers {
			if _, _, ok := bearerJWT(header.Value); ok {
				found = true
				break
			}
		}
		if !found {
			return false, "请求头中没有 JWT"
		}
	case "proxy_trust_bypass":
		if len(httpraw.SessionPoints(request, httpraw.EffectiveSessionIdentifiers(request, cfg.SessionIdentifiers))) == 0 {
			return false, "请求中没有可移除的会话凭据"
		}
	case "csrf":
		if request.Header("Cookie") == "" || (request.Method != "POST" && request.Method != "PUT" && request.Method != "PATCH" && request.Method != "DELETE") {
			return false, "不是基于 Cookie 的状态变更请求"
		}
	case "method_override":
		if request.Method != "POST" && request.Method != "PUT" && request.Method != "PATCH" {
			return false, "当前方法不适合 Method Override 探测"
		}
	case "file_read", "file_read_encoded", "ssrf", "open_redirect", "idor":
		if !hasNamed(cfg.PluginRules[id].ParameterNames) {
			return false, "没有匹配插件语义的参数"
		}
	case "sms_abuse":
		if !smsURLMatches(request, cfg.PluginRules[id].URLKeywords) {
			return false, "URL 未匹配短信接口关键字"
		}
		if !hasNamed(cfg.PluginRules[id].ParameterNames) {
			return false, "没有匹配手机号语义的参数"
		}
	case "command_injection", "command_injection_oast", "command_injection_timing":
		if !hasNamed(cfg.PluginRules[id].ParameterNames) && !hasNamed(cfg.CommandParameterNames) {
			return false, "没有命令类候选参数"
		}
	case "ldap_injection":
		if !hasNamed([]string{"user", "username", "uid", "cn", "dn", "filter", "search", "query", "email", "account"}) {
			return false, "没有 LDAP 查询候选参数"
		}
	case "xpath_injection":
		if !strings.Contains(contentType, "xml") && !hasNamed([]string{"user", "username", "xpath", "query", "search", "filter", "name"}) {
			return false, "没有 XPath 查询候选参数"
		}
	case "nosql_injection":
		if !strings.Contains(contentType, "json") && !hasNamed([]string{"user", "username", "filter", "query", "search", "where", "id"}) {
			return false, "没有 NoSQL 查询候选输入"
		}
	case "sqli", "sqli_extended", "sqli_timing", "error_disclosure", "error_disclosure_extended", "reflected_xss", "ssti", "crlf_injection", "java_expression", "java_expression_extended":
		if !hasPoints {
			return false, "没有可变异输入点"
		}
	}
	return true, ""
}

func estimateRequests(id string, request *httpraw.Request, points []httpraw.InsertionPoint, mode string, cfg config.Config) int {
	count := max(estimatedPointCount(id, points, cfg), 1)
	switch id {
	case "sqli":
		payloads := payloadsForMode(cfg.PluginRules[id], mode)
		errorPairs := pairPayloads(payloads, "error_break", "error_repair")
		conditionalPairs := pairPayloads(payloads, "conditional_control", "conditional_error")
		booleanPairs := pairPayloads(payloads, "boolean_true", "boolean_false")
		timePairs := pairPayloads(payloads, "time_control", "time_delay")
		// The core plugin always runs its quote pair plus one value-appropriate
		// Boolean pair. Extended and timing rules are separate plugin IDs.
		booleanPairCount := 0
		if len(booleanPairs) > 0 {
			booleanPairCount = 1
		}
		// Every slot the runtime can either send or explicitly resolve must be in
		// the plan. The quote gate often prunes most of these slots, but a positive
		// gate can exercise the bounded dialect fallbacks.
		paired := (len(errorPairs) + len(conditionalPairs) + booleanPairCount + len(timePairs)) * 4
		gates := 0
		if len(errorPairs) > 0 {
			gates = 1
		}
		return count * (paired + gates)
	case "sqli_extended":
		payloads := payloadsForMode(cfg.PluginRules[id], mode)
		return count * (len(pairPayloads(payloads, "error_break", "error_repair")) + len(pairPayloads(payloads, "boolean_true", "boolean_false"))) * 4
	case "sqli_timing":
		return count * len(pairPayloads(payloadsForMode(cfg.PluginRules[id], mode), "time_control", "time_delay")) * 4
	case "sqli_order_by":
		payloads := payloadsForMode(cfg.PluginRules[id], mode)
		conditionalPairs := pairPayloads(payloads, "conditional_control", "conditional_error")
		timePairs := pairPayloads(payloads, "time_control", "time_delay")
		total := 0
		for _, point := range namedSQLContextPoints(points, cfg.PluginRules[id].ParameterNames) {
			total += (len(orderByPairsForPoint(conditionalPairs, point)) + len(orderByPairsForPoint(timePairs, point))) * 4
		}
		return total
	case "sqli_limit":
		return len(namedSQLContextPoints(points, cfg.PluginRules[id].ParameterNames)) *
			len(pairPayloads(payloadsForMode(cfg.PluginRules[id], mode), "error_break", "error_repair")) * 4
	case "error_disclosure":
		// Core mode sends one type-aware trigger, then only suspicious responses
		// receive a control and repetition request.
		return count * 3
	case "error_disclosure_extended":
		payloads := payloadsForMode(cfg.PluginRules[id], mode)
		return count * len(payloads) * 3
	case "nosql_injection":
		return count * 6
	case "ldap_injection", "xpath_injection":
		return count * 5
	case "reflected_xss":
		return count * max(1, len(cfg.PluginRules[id].Payloads))
	case "ssrf":
		candidates := 0
		for _, point := range points {
			if semanticName(point.Name, cfg.PluginRules[id].ParameterNames) {
				candidates++
			}
		}
		return candidates * len(payloadsForMode(cfg.PluginRules[id], mode))
	case "command_injection", "command_injection_oast", "command_injection_timing":
		candidates := 0
		names := append(append([]string(nil), cfg.PluginRules[id].ParameterNames...), cfg.CommandParameterNames...)
		for _, point := range points {
			if semanticName(point.Name, names) {
				candidates++
			}
		}
		payloads := payloadsForMode(cfg.PluginRules[id], mode)
		checks := (len(payloadsByKind(payloads, "output"))+len(payloadsByKind(payloads, "direct_output")))*3 +
			len(payloadsByKind(payloads, "callback")) + len(pairPayloads(payloads, "delay", "control"))*2
		return candidates * checks
	case "file_read", "file_read_encoded", "open_redirect", "ssti", "crlf_injection":
		multiplier := 1
		if id == "file_read" {
			multiplier = 2
		} else if id == "ssti" {
			multiplier = 2
		}
		return count * max(1, len(payloadsForMode(cfg.PluginRules[id], mode))) * multiplier
	case "graphql_security", "graphql_alias_abuse":
		return max(1, len(payloadsForMode(cfg.PluginRules[id], mode))*2)
	case "java_deserialization":
		return count * max(1, len(payloadsForMode(cfg.PluginRules[id], mode))) * 2
	case "method_override":
		return max(1, len(payloadsForMode(cfg.PluginRules[id], mode))*3)
	case "mass_assignment", "mass_assignment_extended":
		total := 0
		for _, payload := range payloadsForMode(cfg.PluginRules[id], mode) {
			total += len(massAssignmentVariants(request, payload, id == "mass_assignment_extended")) * 3
		}
		return max(1, total)
	case "mybatis_dynamic_sql":
		payloadCount := 0
		for _, payload := range payloadsForMode(cfg.PluginRules[id], mode) {
			if payload.Kind == "fragment_break" && payload.Mode != "deep" {
				payloadCount++
			}
		}
		// MyBatis uses two fresh canary requests around two already-captured
		// baseline samples. Re-sending the original request could repeat a POST.
		return len(myBatisFragmentPoints(points, cfg.PluginRules[id].ParameterNames)) * payloadCount * 2
	case "path_normalization":
		return 9
	case "parameter_confusion":
		candidates := count + len(httpraw.SessionPoints(request, cfg.SessionIdentifiers))
		return min(candidates, 12) * 4
	case "sms_abuse":
		if !smsURLMatches(request, cfg.PluginRules[id].URLKeywords) {
			return 0
		}
		return smsBatchSize * 2
	case "json_polymorphic":
		paths := len(jsonBindingPaths(request.Body, "@type"))
		return max(1, len(payloadsForMode(cfg.PluginRules[id], mode))*max(paths, 1)*3)
	case "java_expression", "java_expression_extended", "host_header_injection":
		multiplier := count
		if id == "host_header_injection" {
			multiplier = 1
		}
		return multiplier * len(payloadsForMode(cfg.PluginRules[id], mode)) * 2
	case "jndi_injection":
		total := 0
		for _, payload := range payloadsForMode(cfg.PluginRules[id], mode) {
			if payload.Header != "" {
				total++
			} else {
				total += len(points)
			}
		}
		return total
	case "shiro":
		return 1 + len(payloadsForMode(cfg.PluginRules[id], mode))
	case "jwt_active":
		return max(1, len(jwtCandidates(request, points))*3)
	case "proxy_trust_bypass":
		return 9
	case "http_trace":
		return 1
	case "xxe", "xxe_extended":
		xmlPoints := 0
		for _, point := range points {
			if point.Location == "xml" || point.Location == "xml_cdata" {
				xmlPoints++
			}
		}
		return max(1, xmlPoints) * len(payloadsForMode(cfg.PluginRules[id], mode))
	case "unauthorized":
		return 2
	case "file_upload", "file_upload_execution":
		return max(1, len(request.MultipartFiles())) * max(1, len(payloadsForMode(cfg.PluginRules[id], mode))*2)
	case "cors":
		return max(1, len(payloadsForMode(cfg.PluginRules[id], mode)))
	case "api_exposure", "spring_actuator":
		paths := cfg.PluginRules[id].Paths
		return max(1, len(contextualPaths(request, paths)))
	case "csrf":
		return 1
	case "idor":
		return count * 2
	default:
		if strings.Contains(PluginMetaRisk(id), "passive") {
			return 0
		}
		return 1
	}
}

func estimatedPointCount(id string, points []httpraw.InsertionPoint, cfg config.Config) int {
	switch id {
	case "sqli", "sqli_extended", "sqli_timing":
		return len(prioritizeSQLPoints(points))
	case "sqli_order_by", "sqli_limit":
		return len(namedSQLContextPoints(points, cfg.PluginRules[id].ParameterNames))
	case "mybatis_dynamic_sql":
		return len(myBatisFragmentPoints(points, cfg.PluginRules[id].ParameterNames))
	default:
		return len(points)
	}
}

func planBudgetQuantum(id string) int {
	switch id {
	case "sqli":
		// The core SQL plugin has a one-request applicability gate followed by
		// atomic four-request A-B-B-A cohorts. Keep planner allocation granular;
		// RequestCohort enforces that the paired observations are never split.
		return 1
	case "sqli_extended", "sqli_timing", "sqli_order_by", "sqli_limit":
		return 4
	case "mybatis_dynamic_sql":
		return 2
	default:
		return 1
	}
}

// PlanBudgetQuantum exposes the planner's minimum allocation unit to the
// engine's runtime reclaim pool. Atomicity itself remains enforced by
// RequestCohort, so a caller cannot create a half SQL observation.
func PlanBudgetQuantum(id string) int {
	return planBudgetQuantum(id)
}

func pluginPriority(id string) int {
	switch id {
	case "sqli", "sqli_extended", "sqli_timing", "sqli_order_by", "sqli_limit", "mybatis_dynamic_sql", "error_disclosure", "error_disclosure_extended", "file_read", "file_read_encoded", "unauthorized", "command_injection", "command_injection_oast", "command_injection_timing", "xxe", "xxe_extended", "shiro", "java_expression", "java_expression_extended", "jndi_injection", "jwt_active", "proxy_trust_bypass":
		return 4
	case "reflected_xss", "nosql_injection", "ldap_injection", "xpath_injection", "cors", "crlf_injection", "path_normalization", "parameter_confusion":
		return 3
	case "mass_assignment", "mass_assignment_extended", "method_override", "java_deserialization", "json_polymorphic", "file_upload", "file_upload_execution", "idor", "csrf", "sms_abuse", "graphql_alias_abuse":
		return 2
	default:
		return 1
	}
}

func PluginMetaRisk(id string) string {
	for _, item := range registry {
		if item.Meta().ID == id {
			return item.Meta().Risk
		}
	}
	return ""
}
