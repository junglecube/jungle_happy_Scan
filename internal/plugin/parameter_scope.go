package plugin

import (
	"strings"

	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/httpraw"
)

// ParameterCandidates exposes the same point selection rules used by a
// plugin's scanner without sending a request. It is used by the parse UI and
// intentionally returns descriptors without values.
func ParameterCandidates(item Plugin, request *httpraw.Request, points []httpraw.InsertionPoint, cfg config.Config) []httpraw.ParameterDescriptor {
	if item == nil || request == nil {
		return nil
	}
	id := item.Meta().ID
	rule := cfg.PluginRules[id]
	selected := make([]httpraw.InsertionPoint, 0, len(points))
	appendIf := func(predicate func(httpraw.InsertionPoint) bool) {
		for _, point := range points {
			if predicate(point) {
				selected = append(selected, point)
			}
		}
	}
	all := func(point httpraw.InsertionPoint) bool { return true }
	byName := func(names []string) func(httpraw.InsertionPoint) bool {
		return func(point httpraw.InsertionPoint) bool { return semanticName(point.Name, names) }
	}
	switch id {
	case "sqli", "sqli_deep", "sqli_extended", "sqli_timing":
		selected = prioritizeSQLPoints(points)
	case "sqli_order_by", "sqli_limit":
		selected = namedSQLContextPoints(points, rule.ParameterNames)
	case "mybatis_dynamic_sql":
		selected = myBatisFragmentPoints(points, rule.ParameterNames)
	case "file_read", "file_read_encoded":
		appendIf(func(point httpraw.InsertionPoint) bool { return fileReadPoint(point, rule.ParameterNames) })
	case "file_upload", "file_upload_execution":
		appendIf(func(point httpraw.InsertionPoint) bool { return point.Location == "multipart_filename" })
	case "xxe", "xxe_extended":
		appendIf(xxePoint)
	case "sms_abuse":
		if smsURLMatches(request, rule.URLKeywords) {
			appendIf(func(point httpraw.InsertionPoint) bool {
				return controlledSemanticName(point.Name, rule.ParameterNames)
			})
		}
	case "ssrf", "open_redirect", "idor":
		appendIf(byName(rule.ParameterNames))
		if id == "idor" {
			selected = selected[:0]
			appendIf(func(point httpraw.InsertionPoint) bool {
				return semanticName(point.Name, rule.ParameterNames) && isUnsignedInteger(point.Value)
			})
		}
	case "command_injection", "command_injection_oast", "command_injection_timing":
		names := append(append([]string(nil), rule.ParameterNames...), cfg.CommandParameterNames...)
		appendIf(byName(names))
	case "ldap_injection":
		appendIf(byName([]string{"user", "username", "uid", "cn", "dn", "filter", "search", "query", "email", "account"}))
	case "xpath_injection":
		appendIf(byName([]string{"user", "username", "xpath", "query", "search", "filter", "name"}))
	case "nosql_injection":
		appendIf(byName([]string{"user", "username", "filter", "query", "search", "where", "id"}))
	case "java_deserialization":
		appendIf(func(point httpraw.InsertionPoint) bool {
			return looksSerialized(strings.TrimSpace(point.Value)) || semanticName(point.Name, rule.ParameterNames)
		})
	case "jwt_active":
		// jwtCandidates also covers bearer headers and cookies that are not
		// regular mutation points; represent those directly for the preview.
		for _, candidate := range jwtCandidatesScopedExcluded(request, points, nil, cfg.ExcludedParameterNames) {
			if candidate.point != nil {
				selected = append(selected, *candidate.point)
				continue
			}
			selected = append(selected, httpraw.InsertionPoint{Location: "header", Name: candidate.header, Path: candidate.header, ValueType: "string"})
		}
	case "parameter_confusion":
		selected = append(selected, points...)
		for _, point := range httpraw.SessionPoints(request, cfg.SessionIdentifiers) {
			if !containsInsertionPoint(selected, point) && !httpraw.IsExcludedInsertionPoint(point, cfg.ExcludedParameterNames) {
				selected = append(selected, point)
			}
		}
	case "path_normalization", "proxy_trust_bypass":
		for _, point := range httpraw.SessionPoints(request, httpraw.EffectiveSessionIdentifiers(request, cfg.SessionIdentifiers)) {
			if !httpraw.IsExcludedInsertionPoint(point, cfg.ExcludedParameterNames) {
				selected = append(selected, point)
			}
		}
	case "reflected_xss", "reflected_xss_deep", "error_disclosure", "error_disclosure_extended", "ssti", "crlf_injection", "java_expression", "java_expression_extended", "jndi_injection", "host_header_injection", "mass_assignment", "mass_assignment_extended", "json_polymorphic":
		appendIf(all)
	default:
		// Passive, fixed-path, and response-only plugins do not mutate a
		// parameter. Returning an empty list is clearer than showing points that
		// the selected plugin will never use.
	}
	return httpraw.DescribeParameterPoints(selected)
}

func containsInsertionPoint(points []httpraw.InsertionPoint, candidate httpraw.InsertionPoint) bool {
	for _, point := range points {
		if point.Location == candidate.Location && point.Path == candidate.Path && strings.EqualFold(point.Name, candidate.Name) {
			return true
		}
	}
	return false
}

// ScopedMultipartFiles applies the same scope selectors to file names that are
// not represented by a mutable text insertion point at runtime.
func ScopedMultipartFiles(request *httpraw.Request, selectors []string) []httpraw.MultipartFile {
	files := request.MultipartFiles()
	if len(selectors) == 0 {
		return files
	}
	selected := make([]httpraw.MultipartFile, 0, len(files))
	for _, file := range files {
		point := httpraw.InsertionPoint{Location: "multipart_filename", Name: file.FieldName, Path: file.FieldName, Value: file.Filename, ValueType: "string"}
		if httpraw.MatchesParameterScope(point, selectors) {
			selected = append(selected, file)
		}
	}
	return selected
}

func scopedSessionPoints(request *httpraw.Request, cfg config.Config, selectors []string, effective bool) []httpraw.InsertionPoint {
	identifiers := cfg.SessionIdentifiers
	if effective {
		identifiers = httpraw.EffectiveSessionIdentifiers(request, identifiers)
	}
	points := httpraw.SessionPoints(request, identifiers)
	selected := make([]httpraw.InsertionPoint, 0, len(points))
	for _, point := range points {
		if httpraw.IsExcludedInsertionPoint(point, cfg.ExcludedParameterNames) || !httpraw.MatchesParameterScope(point, selectors) {
			continue
		}
		selected = append(selected, point)
	}
	return selected
}

func scopedSessionIdentifiers(request *httpraw.Request, cfg config.Config, selectors []string, effective bool) config.SessionKeyList {
	if len(selectors) == 0 && len(cfg.ExcludedParameterNames) == 0 {
		if effective {
			return httpraw.EffectiveSessionIdentifiers(request, cfg.SessionIdentifiers)
		}
		return append(config.SessionKeyList(nil), cfg.SessionIdentifiers...)
	}
	points := scopedSessionPoints(request, cfg, selectors, effective)
	result := make(config.SessionKeyList, 0, len(points))
	seen := make(map[string]bool)
	for _, point := range points {
		key := strings.ToLower(strings.TrimSpace(point.Name))
		if key != "" && !seen[key] {
			seen[key] = true
			result = append(result, point.Name)
		}
	}
	return result
}
