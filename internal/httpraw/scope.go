package httpraw

import "strings"

// ParameterDescriptor is the safe, value-free representation returned by the
// parse endpoint. Values are deliberately omitted because parsing a request
// must not echo credentials or other sensitive input back to the browser.
type ParameterDescriptor struct {
	Selector  string `json:"selector"`
	Name      string `json:"name"`
	Location  string `json:"location"`
	Path      string `json:"path,omitempty"`
	ValueType string `json:"value_type,omitempty"`
}

// NormalizeParameterScope accepts the textarea-friendly forms
// "[id]", "id", or one comma/newline separated list. Empty selectors mean
// that the caller did not request a restriction.
func NormalizeParameterScope(values []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(values))
	for _, raw := range values {
		for _, part := range strings.FieldsFunc(raw, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' }) {
			selector := strings.TrimSpace(part)
			if len(selector) >= 2 && strings.HasPrefix(selector, "[") && strings.HasSuffix(selector, "]") {
				selector = strings.TrimSpace(selector[1 : len(selector)-1])
			}
			if selector == "" {
				continue
			}
			key := strings.ToLower(selector)
			if seen[key] {
				continue
			}
			seen[key] = true
			result = append(result, selector)
			if len(result) >= 256 {
				return result
			}
		}
	}
	return result
}

// MatchesParameterScope uses exact, case-insensitive selectors. A selector
// can be a parameter name/path ("number"), a location-qualified name
// ("query:number"), or the full insertion-point label ("json:user.id").
// Exact matching prevents an operator selecting [id] from unintentionally
// mutating [userid] or [id2].
func MatchesParameterScope(point InsertionPoint, selectors []string) bool {
	if len(selectors) == 0 {
		return true
	}
	values := make([]string, 0, 10)
	for current := &point; current != nil; current = current.parent {
		values = append(values, current.Name, current.Path, current.Label(), current.Location+":"+current.Name, current.Location+":"+current.Path)
	}
	for _, selector := range NormalizeParameterScope(selectors) {
		for _, value := range values {
			if value != "" && strings.EqualFold(strings.TrimSpace(selector), strings.TrimSpace(value)) {
				return true
			}
		}
	}
	return false
}

// FilterInsertionPoints applies the optional per-scan scope after persistent
// exclusions have already been applied by DiscoverAdvanced.
func FilterInsertionPoints(points []InsertionPoint, selectors []string) []InsertionPoint {
	selectors = NormalizeParameterScope(selectors)
	if len(selectors) == 0 {
		return append([]InsertionPoint(nil), points...)
	}
	filtered := make([]InsertionPoint, 0, len(points))
	for _, point := range points {
		if MatchesParameterScope(point, selectors) {
			filtered = append(filtered, point)
		}
	}
	return filtered
}

// DescribeParameterPoints returns deterministic, deduplicated selectors for
// the frontend. Duplicate names are made location-qualified so an edited
// textarea remains unambiguous while common unique fields stay concise.
func DescribeParameterPoints(points []InsertionPoint) []ParameterDescriptor {
	counts := make(map[string]int)
	for _, point := range points {
		name := strings.TrimSpace(point.Name)
		if name == "" {
			name = strings.TrimSpace(point.Path)
		}
		if name != "" {
			counts[strings.ToLower(name)]++
		}
	}
	seen := make(map[string]bool)
	result := make([]ParameterDescriptor, 0, len(points))
	for _, point := range points {
		name := strings.TrimSpace(point.Name)
		if name == "" {
			name = strings.TrimSpace(point.Path)
		}
		if name == "" {
			continue
		}
		selector := name
		if counts[strings.ToLower(name)] > 1 {
			selector = point.Location + ":" + name
		}
		key := strings.ToLower(selector)
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, ParameterDescriptor{Selector: selector, Name: point.Name, Location: point.Location, Path: point.Path, ValueType: point.ValueType})
	}
	return result
}
