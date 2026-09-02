package httpraw

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"jungle_happy_Scan/internal/config"
)

type InsertionPoint struct {
	Location   string `json:"location"`
	Name       string `json:"name"`
	Path       string `json:"path"`
	Value      string `json:"value"`
	Occurrence int    `json:"occurrence"`
	ValueType  string `json:"value_type"`
	start      int
	end        int
	parent     *InsertionPoint
	nested     *InsertionPoint
	encoding   string
}

var (
	lexicalNumberPattern = regexp.MustCompile(`^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$`)
	lexicalDatePattern   = regexp.MustCompile(`^\d{4}[-/]\d{2}[-/]\d{2}(?:[T ][0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:\.\d+)?)?(?:Z|[+-][0-9]{2}:?[0-9]{2})?)?$`)
	lexicalUUIDPattern   = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

// lexicalValueType classifies scalar values carried by text-oriented
// containers. Query strings, forms and multipart text fields do not preserve a
// native JSON type, but knowing that a captured value is a numeric literal is
// important when a scanner selects syntax-safe SQL probes. Mutation still
// writes the supplied text verbatim; this metadata must never coerce or
// reformat the original request.
func lexicalValueType(value string) string {
	trimmed := strings.TrimSpace(value)
	switch {
	case lexicalDatePattern.MatchString(trimmed):
		return "date"
	case strings.EqualFold(trimmed, "true") || strings.EqualFold(trimmed, "false"):
		return "bool"
	case lexicalUUIDPattern.MatchString(trimmed):
		return "uuid"
	case lexicalNumberPattern.MatchString(trimmed):
		return "number"
	default:
		return "string"
	}
}

func isJSONRequestBody(contentType string, body []byte) bool {
	lower := strings.ToLower(contentType)
	if strings.Contains(lower, "application/json") || strings.Contains(lower, "+json") {
		return len(bytes.TrimSpace(body)) > 0
	}
	trimmed := bytes.TrimSpace(body)
	return len(trimmed) > 1 && (trimmed[0] == '{' || trimmed[0] == '[') && json.Valid(trimmed)
}

func escapeXMLAttribute(value string) string {
	return strings.NewReplacer("&", "&amp;", `"`, "&quot;", "<", "&lt;", ">", "&gt;").Replace(value)
}

func (p InsertionPoint) Label() string {
	name := p.Name
	if p.Path != "" {
		name = p.Path
	}
	return p.Location + ":" + name
}

func Discover(req *Request, includeHeaders bool) []InsertionPoint {
	var points []InsertionPoint
	if u, err := url.Parse(req.Target); err == nil {
		points = append(points, discoverPairs("query", u.RawQuery)...)
	}
	ctype := req.ContentType()
	body := string(req.Body)
	switch {
	case isJSONRequestBody(ctype, req.Body):
		if jsonPoints, err := discoverJSONPoints(req.Body); err == nil {
			points = append(points, jsonPoints...)
			for index := range points {
				if strings.HasPrefix(points[index].Path, "variables.") || strings.HasPrefix(points[index].Path, "variables[") {
					points[index].Location = "graphql_variable"
				}
			}
		}
	case strings.Contains(ctype, "application/x-www-form-urlencoded"):
		points = append(points, discoverPairs("form", body)...)
	case strings.Contains(ctype, "xml") || strings.HasPrefix(strings.TrimSpace(body), "<"):
		re := regexp.MustCompile(`(?s)<([A-Za-z_][\w:.-]*)[^>]*>([^<>]{0,1000})</[A-Za-z_][\w:.-]*>`)
		elementOccurrences := map[string]int{}
		for _, match := range re.FindAllStringSubmatch(body, -1) {
			occurrence := elementOccurrences[match[1]]
			elementOccurrences[match[1]]++
			points = append(points, InsertionPoint{Location: "xml", Name: match[1], Path: fmt.Sprintf("%s[%d]", match[1], occurrence), Value: match[2], Occurrence: occurrence, ValueType: "string"})
		}
		attrRE := regexp.MustCompile(`(?s)([A-Za-z_][\w:.-]*)\s*=\s*"([^"]{0,1000})"`)
		attributeOccurrences := map[string]int{}
		for _, match := range attrRE.FindAllStringSubmatch(body, -1) {
			occurrence := attributeOccurrences[match[1]]
			attributeOccurrences[match[1]]++
			points = append(points, InsertionPoint{Location: "xml_attribute", Name: match[1], Path: fmt.Sprintf("@%s[%d]", match[1], occurrence), Value: match[2], Occurrence: occurrence, ValueType: "string"})
		}
		cdataRE := regexp.MustCompile(`(?s)<!\[CDATA\[(.*?)\]\]>`)
		for index, match := range cdataRE.FindAllStringSubmatch(body, -1) {
			value := match[1]
			if len(value) > 4000 {
				value = value[:4000]
			}
			points = append(points, InsertionPoint{Location: "xml_cdata", Name: fmt.Sprintf("cdata_%d", index), Path: strconv.Itoa(index), Value: value, ValueType: "string"})
		}
	case strings.Contains(ctype, "multipart/form-data"):
		points = append(points, discoverMultipart(req)...)
	}
	if includeHeaders {
		safe := map[string]bool{"x-forwarded-for": true, "x-original-url": true, "referer": true, "user-agent": true}
		for _, h := range req.Headers {
			if safe[strings.ToLower(h.Name)] {
				points = append(points, InsertionPoint{Location: "header", Name: h.Name, Path: h.Name, Value: h.Value, ValueType: "string"})
			}
		}
	}
	return dedupe(points)
}

func DiscoverAdvanced(req *Request, cfg config.Config) []InsertionPoint {
	points := Discover(req, false)
	points = append(points, discoverPathSegments(req)...)
	points = append(points, discoverBusinessCookies(req, cfg.SessionIdentifiers)...)
	for _, headerName := range cfg.ScanHeaderNames {
		if value := req.Header(headerName); value != "" {
			points = append(points, InsertionPoint{Location: "header", Name: headerName, Path: headerName, Value: value, ValueType: "string"})
		}
	}
	filtered := points[:0]
	for _, point := range points {
		if !excludedInsertionPoint(point, cfg.ExcludedParameterNames) {
			filtered = append(filtered, point)
		}
	}
	points = filtered
	base := append([]InsertionPoint(nil), points...)
	for _, point := range base {
		if point.ValueType != "string" {
			continue
		}
		for _, nestedPoint := range discoverNestedPoints(point, []byte(point.Value), "", cfg.ExcludedParameterNames, 0) {
			points = append(points, nestedPoint)
		}
		if len(point.Value) >= 8 {
			if decoded, encoding := decodePossibleBase64(point.Value); encoding != "" {
				for _, nestedPoint := range discoverNestedPoints(point, decoded, encoding, cfg.ExcludedParameterNames, 0) {
					points = append(points, nestedPoint)
				}
			}
		}
	}
	return dedupe(points)
}

func excludedParameter(name string, excluded []string) bool {
	name = strings.TrimSpace(name)
	for _, candidate := range excluded {
		if name != "" && strings.EqualFold(name, strings.TrimSpace(candidate)) {
			return true
		}
	}
	return false
}

func excludedInsertionPoint(point InsertionPoint, excluded []string) bool {
	if excludedParameter(point.Name, excluded) {
		return true
	}
	if point.Location != "json" && point.Location != "graphql_variable" {
		return false
	}
	for _, token := range parsePath(point.Path) {
		if token.index < 0 && excludedParameter(token.key, excluded) {
			return true
		}
	}
	return false
}

// discoverNestedPoints turns a parameter whose value is itself JSON or XML
// into ordinary leaf insertion points. The parent chain is retained in memory,
// so Mutate can rebuild the inner document, restore Base64 when present, and
// finally write the value back through query/form/header/JSON/cookie handling.
func discoverNestedPoints(parent InsertionPoint, raw []byte, encoding string, excluded []string, depth int) []InsertionPoint {
	if depth >= 3 || len(raw) == 0 || len(raw) > 1_000_000 {
		return nil
	}
	trimmed := bytes.TrimSpace(raw)
	var inner []InsertionPoint
	format := ""
	var value any
	if len(trimmed) > 1 && (trimmed[0] == '{' || trimmed[0] == '[') && decodeJSONAny(trimmed, &value) == nil {
		switch value.(type) {
		case map[string]any, []any:
			walkJSON(value, "", &inner)
			format = "json"
		}
	} else if len(trimmed) > 2 && trimmed[0] == '<' {
		synthetic := &Request{Body: append([]byte(nil), trimmed...), Headers: []Header{{Name: "Content-Type", Value: "application/xml"}}}
		inner = Discover(synthetic, false)
		format = "xml"
	}
	if format == "" {
		return nil
	}
	result := make([]InsertionPoint, 0, len(inner))
	parentCopy := parent
	for _, nested := range inner {
		if excludedInsertionPoint(nested, excluded) {
			continue
		}
		nestedCopy := nested
		point := nested
		point.Location = "nested_" + format
		if encoding != "" {
			point.Location = "base64_" + format
		}
		point.Path = parent.Path + " → " + nested.Path
		point.parent = &parentCopy
		point.nested = &nestedCopy
		point.encoding = encoding
		result = append(result, point)
		if nested.ValueType == "string" {
			for _, child := range discoverNestedPoints(point, []byte(nested.Value), "", excluded, depth+1) {
				result = append(result, child)
			}
			if len(nested.Value) >= 8 {
				if decoded, childEncoding := decodePossibleBase64(nested.Value); childEncoding != "" {
					result = append(result, discoverNestedPoints(point, decoded, childEncoding, excluded, depth+1)...)
				}
			}
		}
	}
	return result
}

func Mutate(req *Request, point InsertionPoint, value string) (*Request, error) {
	out := req.Clone()
	switch point.Location {
	case "query":
		u, err := url.Parse(out.Target)
		if err != nil {
			return nil, err
		}
		u.RawQuery = replacePair(u.RawQuery, point.Name, point.Occurrence, value)
		out.Target = u.String()
		return out, nil
	case "form":
		out.Body = []byte(replacePair(string(out.Body), point.Name, point.Occurrence, value))
		return out, nil
	case "json":
		encoded, err := encodeJSONMutation(value, point.ValueType)
		if err != nil {
			return nil, err
		}
		out.Body, err = replaceJSONPoint(out.Body, point, encoded)
		if err != nil {
			return nil, err
		}
		return out, nil
	case "graphql_variable":
		copyPoint := point
		copyPoint.Location = "json"
		return Mutate(out, copyPoint, value)
	case "xml":
		re := regexp.MustCompile(`(?s)(<` + regexp.QuoteMeta(point.Name) + `[^>]*>)([^<>]{0,1000})(</` + regexp.QuoteMeta(point.Name) + `>)`)
		out.Body = []byte(replaceNthStringFunc(re, string(out.Body), point.Occurrence, func(match string) string {
			start := strings.Index(match, ">")
			end := strings.LastIndex(match, "</")
			if start < 0 || end < start {
				return match
			}
			return match[:start+1] + value + match[end:]
		}))
		return out, nil
	case "multipart":
		body := string(out.Body)
		marker := `name="` + point.Name + `"`
		at := strings.Index(body, marker)
		if at < 0 {
			return nil, fmt.Errorf("multipart 字段 %q 不存在", point.Name)
		}
		headEnd := strings.Index(body[at:], "\r\n\r\n")
		separator := 4
		if headEnd < 0 {
			headEnd = strings.Index(body[at:], "\n\n")
			separator = 2
		}
		if headEnd < 0 {
			return nil, fmt.Errorf("multipart 字段 %q 格式不完整", point.Name)
		}
		valueStart := at + headEnd + separator
		valueEnd := valueStart + len(point.Value)
		if valueEnd > len(body) {
			return nil, errorsf("multipart 字段值越界")
		}
		out.Body = []byte(body[:valueStart] + value + body[valueEnd:])
		return out, nil
	case "multipart_filename":
		pattern := regexp.MustCompile(`(?i)filename="` + regexp.QuoteMeta(point.Value) + `"`)
		if !pattern.Match(out.Body) {
			return nil, fmt.Errorf("multipart 文件名 %q 不存在", point.Value)
		}
		out.Body = pattern.ReplaceAll(out.Body, []byte(`filename="`+value+`"`))
		return out, nil
	case "path":
		u, err := url.Parse(out.Target)
		if err != nil {
			return nil, err
		}
		segments := strings.Split(u.EscapedPath(), "/")
		index, err := strconv.Atoi(point.Path)
		if err != nil || index < 0 || index >= len(segments) {
			return nil, errorsf("URL 路径插入点无效")
		}
		segments[index] = url.PathEscape(value)
		u.RawPath = strings.Join(segments, "/")
		u.Path, _ = url.PathUnescape(u.RawPath)
		out.Target = u.String()
		return out, nil
	case "cookie":
		for index, header := range out.Headers {
			if !strings.EqualFold(header.Name, "Cookie") {
				continue
			}
			parts := strings.Split(header.Value, ";")
			for partIndex, part := range parts {
				name, _, ok := strings.Cut(strings.TrimSpace(part), "=")
				if ok && strings.EqualFold(name, point.Name) {
					parts[partIndex] = name + "=" + value
					out.Headers[index].Value = strings.Join(parts, "; ")
					return out, nil
				}
			}
		}
		return nil, fmt.Errorf("Cookie %q 不存在", point.Name)
	case "xml_attribute":
		pattern := regexp.MustCompile(`(` + regexp.QuoteMeta(point.Name) + `\s*=\s*")([^"]{0,1000})"`)
		out.Body = []byte(replaceNthStringFunc(pattern, string(out.Body), point.Occurrence, func(match string) string {
			start := strings.Index(match, `"`)
			end := strings.LastIndex(match, `"`)
			if start < 0 || end <= start {
				return match
			}
			return match[:start+1] + escapeXMLAttribute(value) + match[end:]
		}))
		return out, nil
	case "xml_cdata":
		pattern := regexp.MustCompile(`(?s)(<!\[CDATA\[)` + regexp.QuoteMeta(point.Value) + `(\]\]>)`)
		out.Body = pattern.ReplaceAll(out.Body, []byte(`${1}`+value+`${2}`))
		return out, nil
	case "base64_json":
		if point.parent != nil && point.nested != nil {
			return mutateNested(req, point, value)
		}
		return mutateBase64JSON(out, point, value)
	case "nested_json", "nested_xml", "base64_xml":
		return mutateNested(req, point, value)
	case "header":
		return out.WithHeader(point.Name, value), nil
	default:
		return nil, fmt.Errorf("不支持的插入点位置 %q", point.Location)
	}
}

func mutateNested(req *Request, point InsertionPoint, value string) (*Request, error) {
	if point.parent == nil || point.nested == nil {
		return nil, errorsf("嵌套插入点缺少父级信息")
	}
	raw := []byte(point.parent.Value)
	if point.encoding != "" {
		encodings := map[string]*base64.Encoding{
			"std": base64.StdEncoding, "rawstd": base64.RawStdEncoding,
			"url": base64.URLEncoding, "rawurl": base64.RawURLEncoding,
		}
		decoder := encodings[point.encoding]
		if decoder == nil {
			return nil, errorsf("嵌套 Base64 编码无效")
		}
		decoded, decodeErr := decoder.DecodeString(point.parent.Value)
		if decodeErr != nil || len(decoded) == 0 {
			return nil, errorsf("嵌套 Base64 外层值无效")
		}
		raw = decoded
	}
	var mutated []byte
	var err error
	switch {
	case strings.HasSuffix(point.Location, "_json"):
		encoded, encodeErr := encodeJSONMutation(value, point.nested.ValueType)
		if encodeErr != nil {
			return nil, encodeErr
		}
		mutated, err = replaceJSONPoint(raw, *point.nested, encoded)
	case strings.HasSuffix(point.Location, "_xml"):
		synthetic := &Request{Body: append([]byte(nil), raw...)}
		changed, mutateErr := Mutate(synthetic, *point.nested, value)
		if mutateErr != nil {
			return nil, mutateErr
		}
		mutated = changed.Body
	default:
		return nil, fmt.Errorf("不支持的嵌套格式 %q", point.Location)
	}
	if err != nil {
		return nil, err
	}
	outerValue := string(mutated)
	if point.encoding != "" {
		encodings := map[string]*base64.Encoding{
			"std": base64.StdEncoding, "rawstd": base64.RawStdEncoding,
			"url": base64.URLEncoding, "rawurl": base64.RawURLEncoding,
		}
		encoder := encodings[point.encoding]
		if encoder == nil {
			return nil, errorsf("嵌套 Base64 编码无效")
		}
		outerValue = encoder.EncodeToString(mutated)
	}
	return Mutate(req, *point.parent, outerValue)
}

// MutateJSONRaw replaces a JSON insertion point with a typed JSON value. It is
// used by operator/type-confusion probes such as NoSQL injection; non-JSON
// points fall back to the normal string mutation behavior.
func MutateJSONRaw(req *Request, point InsertionPoint, rawValue string) (*Request, error) {
	if point.Location != "json" {
		return Mutate(req, point, rawValue)
	}
	if !json.Valid([]byte(rawValue)) {
		return nil, errorsf("JSON 变异值无效")
	}
	out := req.Clone()
	encoded, err := replaceJSONPoint(out.Body, point, []byte(rawValue))
	if err != nil {
		return nil, err
	}
	out.Body = encoded
	return out, nil
}

// MutateParameterNameValue changes one query/form parameter occurrence and is
// used for bracket-style operators such as user[$ne]=x.
func MutateParameterNameValue(req *Request, point InsertionPoint, name, value string) (*Request, error) {
	out := req.Clone()
	switch point.Location {
	case "query":
		u, err := url.Parse(out.Target)
		if err != nil {
			return nil, err
		}
		u.RawQuery = replacePairNameValue(u.RawQuery, point.Name, point.Occurrence, name, value)
		out.Target = u.String()
		return out, nil
	case "form":
		out.Body = []byte(replacePairNameValue(string(out.Body), point.Name, point.Occurrence, name, value))
		return out, nil
	default:
		return nil, fmt.Errorf("位置 %q 不支持参数名变异", point.Location)
	}
}

// AddJSONField adds a configurable field path to an existing JSON object. New
// leaf fields are allowed, while every parent object must already exist.
func AddJSONField(req *Request, fieldPath, rawValue string) (*Request, error) {
	var replacement any
	if err := decodeJSONAny([]byte(rawValue), &replacement); err != nil {
		return nil, fmt.Errorf("JSON 字段值无效: %w", err)
	}
	var data any
	if err := decodeJSONAny(req.Body, &data); err != nil {
		return nil, err
	}
	tokens := parsePath(fieldPath)
	if len(tokens) == 0 || tokens[len(tokens)-1].index >= 0 {
		return nil, errorsf("新增 JSON 字段路径无效")
	}
	node := &data
	for _, token := range tokens[:len(tokens)-1] {
		if token.index >= 0 {
			array, ok := (*node).([]any)
			if !ok || token.index >= len(array) {
				return nil, errorsf("新增 JSON 字段数组路径无效")
			}
			node = &array[token.index]
			continue
		}
		object, ok := (*node).(map[string]any)
		if !ok {
			return nil, errorsf("新增 JSON 字段对象路径无效")
		}
		child, ok := object[token.key]
		if !ok {
			return nil, errorsf("新增 JSON 字段父路径不存在")
		}
		node = &child
	}
	object, ok := (*node).(map[string]any)
	if !ok {
		return nil, errorsf("新增 JSON 字段父节点不是对象")
	}
	object[tokens[len(tokens)-1].key] = replacement
	encoded, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return req.WithBody(encoded), nil
}

// AddParameter appends a new query, form or multipart text field without
// re-serializing unrelated request content. This is important for pasted Burp
// multipart requests because file bytes and original part headers must remain
// unchanged.
func AddParameter(req *Request, location, name, value string) (*Request, error) {
	if strings.TrimSpace(name) == "" {
		return nil, errorsf("新增参数名不能为空")
	}
	out := req.Clone()
	pair := url.QueryEscape(name) + "=" + url.QueryEscape(value)
	switch location {
	case "query":
		parsed, err := url.Parse(out.Target)
		if err != nil {
			return nil, err
		}
		if parsed.RawQuery == "" {
			parsed.RawQuery = pair
		} else {
			parsed.RawQuery += "&" + pair
		}
		out.Target = parsed.String()
		return out, nil
	case "form":
		if !strings.Contains(out.ContentType(), "application/x-www-form-urlencoded") {
			return nil, errorsf("请求体不是 form-urlencoded")
		}
		if len(out.Body) == 0 {
			out.Body = []byte(pair)
		} else {
			out.Body = append(append(append([]byte(nil), out.Body...), '&'), []byte(pair)...)
		}
		return out, nil
	case "multipart":
		_, params, err := mime.ParseMediaType(out.Header("Content-Type"))
		if err != nil || params["boundary"] == "" {
			return nil, errorsf("multipart boundary 无效")
		}
		boundary := params["boundary"]
		closingCRLF := []byte("\r\n--" + boundary + "--")
		closingLF := []byte("\n--" + boundary + "--")
		index := bytes.LastIndex(out.Body, closingCRLF)
		lineEnding := "\r\n"
		prefixLength := 2
		if index < 0 {
			index = bytes.LastIndex(out.Body, closingLF)
			lineEnding = "\n"
			prefixLength = 1
		}
		if index < 0 {
			return nil, errorsf("multipart 结束边界不存在")
		}
		part := "--" + boundary + lineEnding +
			`Content-Disposition: form-data; name="` + escapeMultipartName(name) + `"` + lineEnding + lineEnding +
			value
		body := make([]byte, 0, len(out.Body)+len(part)+8)
		body = append(body, out.Body[:index+prefixLength]...)
		body = append(body, []byte(part)...)
		body = append(body, out.Body[index:]...)
		out.Body = body
		return out, nil
	default:
		return nil, fmt.Errorf("位置 %q 不支持新增参数", location)
	}
}

// DuplicateParameter creates an explicit first/last duplicate pair. It is used
// to compare gateway/framework precedence without changing any other values.
func DuplicateParameter(req *Request, point InsertionPoint, first, second string) (*Request, error) {
	if point.Location != "query" && point.Location != "form" {
		return nil, fmt.Errorf("位置 %q 不支持重复参数", point.Location)
	}
	out := req.Clone()
	var raw string
	if point.Location == "query" {
		parsed, err := url.Parse(out.Target)
		if err != nil {
			return nil, err
		}
		raw = parsed.RawQuery
		parsed.RawQuery = replacePairWithDuplicate(raw, point.Name, point.Occurrence, first, second)
		out.Target = parsed.String()
		return out, nil
	}
	out.Body = []byte(replacePairWithDuplicate(string(out.Body), point.Name, point.Occurrence, first, second))
	return out, nil
}

// SessionPoints reports every configured credential occurrence regardless of
// whether it appears in a header, Cookie, query, form, nested JSON or multipart.
func SessionPoints(req *Request, identifiers config.SessionKeyList) []InsertionPoint {
	keys := sessionKeySet(identifiers)
	var result []InsertionPoint
	for _, header := range req.Headers {
		lower := strings.ToLower(strings.TrimSpace(header.Name))
		if lower == "cookie" {
			for _, part := range strings.Split(header.Value, ";") {
				name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
				if ok && keys[strings.ToLower(name)] {
					result = append(result, InsertionPoint{Location: "cookie", Name: name, Path: name, Value: value, ValueType: "string"})
				}
			}
		} else if keys[lower] {
			result = append(result, InsertionPoint{Location: "header", Name: header.Name, Path: header.Name, Value: header.Value, ValueType: "string"})
		}
	}
	for _, point := range Discover(req, false) {
		if keys[strings.ToLower(point.Name)] {
			result = append(result, point)
		}
	}
	return dedupe(result)
}

// EffectiveSessionIdentifiers supplements administrator configured keys with
// credential-like names observed in the current request. This prevents a broad
// Cookie key from being removed while a custom desSessionId/token header or
// body field remains valid and causes a false unauthorized finding.
func EffectiveSessionIdentifiers(req *Request, identifiers config.SessionKeyList) config.SessionKeyList {
	result := append(config.SessionKeyList(nil), identifiers...)
	seen := sessionKeySet(result)
	add := func(name string) {
		name = strings.TrimSpace(name)
		lower := strings.ToLower(name)
		if name == "" || seen[lower] || !likelySessionName(lower) {
			return
		}
		seen[lower] = true
		result = append(result, name)
	}
	for _, header := range req.Headers {
		if strings.EqualFold(header.Name, "Cookie") {
			for _, part := range strings.Split(header.Value, ";") {
				name, _, ok := strings.Cut(strings.TrimSpace(part), "=")
				if ok {
					add(name)
				}
			}
			continue
		}
		add(header.Name)
	}
	for _, point := range Discover(req, false) {
		add(point.Name)
	}
	return result
}

func likelySessionName(lower string) bool {
	compact := strings.NewReplacer("_", "", "-", "", ".", "").Replace(lower)
	for _, marker := range []string{"session", "token", "authorization", "accesstoken", "authkey", "ticket", "credential"} {
		if strings.Contains(compact, marker) {
			return true
		}
	}
	return false
}

func RemoveSessions(req *Request, identifiers config.SessionKeyList) (*Request, []string) {
	out := req.Clone()
	keys := sessionKeySet(identifiers)
	if len(keys) == 0 {
		return out, nil
	}
	var removed []string
	filteredHeaders := make([]Header, 0, len(out.Headers))
	for _, header := range out.Headers {
		lowerName := strings.ToLower(strings.TrimSpace(header.Name))
		if lowerName == "cookie" {
			if keys[lowerName] {
				removed = append(removed, "header:"+header.Name)
				continue
			}
			kept := make([]string, 0)
			for _, part := range strings.Split(header.Value, ";") {
				name, _, ok := strings.Cut(strings.TrimSpace(part), "=")
				if ok && keys[strings.ToLower(name)] {
					removed = append(removed, "cookie:"+name)
					continue
				}
				kept = append(kept, strings.TrimSpace(part))
			}
			header.Value = strings.Join(kept, "; ")
			if strings.TrimSpace(header.Value) == "" {
				continue
			}
		} else if keys[lowerName] {
			removed = append(removed, "header:"+header.Name)
			continue
		}
		filteredHeaders = append(filteredHeaders, header)
	}
	out.Headers = filteredHeaders
	out, removed = removeSessionValues(out, keys, removed)
	return out, uniqueStrings(removed)
}

func escapeMultipartName(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, `"`, `\"`)
}

func InvalidateSessions(req *Request, identifiers config.SessionKeyList, invalidValue string) (*Request, []string) {
	out := req.Clone()
	keys := sessionKeySet(identifiers)
	if len(keys) == 0 {
		return out, nil
	}
	var changed []string
	for i := range out.Headers {
		header := &out.Headers[i]
		lowerName := strings.ToLower(strings.TrimSpace(header.Name))
		if lowerName == "cookie" {
			if keys[lowerName] {
				header.Value = invalidValue
				changed = append(changed, "header:"+header.Name)
				continue
			}
			parts := strings.Split(header.Value, ";")
			for j, part := range parts {
				name, _, ok := strings.Cut(strings.TrimSpace(part), "=")
				if ok && keys[strings.ToLower(name)] {
					parts[j] = name + "=" + invalidValue
					changed = append(changed, "cookie:"+name)
				}
			}
			header.Value = strings.Join(parts, ";")
		} else if keys[lowerName] {
			header.Value = invalidValue
			changed = append(changed, "header:"+header.Name)
		}
	}
	out, changed = invalidateSessionValues(out, keys, invalidValue, changed)
	return out, uniqueStrings(changed)
}

func sessionKeySet(identifiers config.SessionKeyList) map[string]bool {
	keys := make(map[string]bool, len(identifiers))
	for _, identifier := range identifiers {
		if key := strings.ToLower(strings.TrimSpace(identifier)); key != "" {
			keys[key] = true
		}
	}
	return keys
}

func removeSessionValues(req *Request, keys map[string]bool, changed []string) (*Request, []string) {
	out := req.Clone()
	if parsed, err := url.Parse(out.Target); err == nil {
		parsed.RawQuery, changed = filterSessionPairs(parsed.RawQuery, "query", keys, "", true, changed)
		out.Target = parsed.String()
	}
	ctype := out.ContentType()
	switch {
	case strings.Contains(ctype, "application/x-www-form-urlencoded"):
		body, updated := filterSessionPairs(string(out.Body), "form", keys, "", true, changed)
		out.Body, changed = []byte(body), updated
	case isJSONRequestBody(ctype, out.Body):
		var value any
		if decodeJSONAny(out.Body, &value) == nil {
			removeJSONSessionKeys(&value, "", keys, &changed)
			if encoded, err := json.Marshal(value); err == nil {
				out.Body = encoded
			}
		}
	case strings.Contains(ctype, "multipart/form-data"):
		for _, point := range Discover(out, false) {
			if point.Location == "multipart" && keys[strings.ToLower(point.Name)] {
				if mutated, err := Mutate(out, point, ""); err == nil {
					out = mutated
					changed = append(changed, "multipart:"+point.Name)
				}
			}
		}
	}
	return out, changed
}

func invalidateSessionValues(req *Request, keys map[string]bool, invalidValue string, changed []string) (*Request, []string) {
	out := req.Clone()
	if parsed, err := url.Parse(out.Target); err == nil {
		parsed.RawQuery, changed = filterSessionPairs(parsed.RawQuery, "query", keys, invalidValue, false, changed)
		out.Target = parsed.String()
	}
	ctype := out.ContentType()
	switch {
	case strings.Contains(ctype, "application/x-www-form-urlencoded"):
		body, updated := filterSessionPairs(string(out.Body), "form", keys, invalidValue, false, changed)
		out.Body, changed = []byte(body), updated
	case isJSONRequestBody(ctype, out.Body):
		var value any
		if decodeJSONAny(out.Body, &value) == nil {
			invalidateJSONSessionKeys(&value, "", keys, invalidValue, &changed)
			if encoded, err := json.Marshal(value); err == nil {
				out.Body = encoded
			}
		}
	case strings.Contains(ctype, "multipart/form-data"):
		for _, point := range Discover(out, false) {
			if point.Location == "multipart" && keys[strings.ToLower(point.Name)] {
				if mutated, err := Mutate(out, point, invalidValue); err == nil {
					out = mutated
					changed = append(changed, "multipart:"+point.Name)
				}
			}
		}
	}
	return out, changed
}

func filterSessionPairs(raw, location string, keys map[string]bool, replacement string, remove bool, changed []string) (string, []string) {
	if raw == "" {
		return raw, changed
	}
	parts := strings.Split(raw, "&")
	output := make([]string, 0, len(parts))
	for _, part := range parts {
		nameRaw, _, hasEqual := strings.Cut(part, "=")
		name, err := url.QueryUnescape(nameRaw)
		if err != nil || !keys[strings.ToLower(name)] {
			output = append(output, part)
			continue
		}
		changed = append(changed, location+":"+name)
		if !remove {
			encoded := url.QueryEscape(replacement)
			if hasEqual || replacement != "" {
				output = append(output, nameRaw+"="+encoded)
			} else {
				output = append(output, nameRaw)
			}
		}
	}
	return strings.Join(output, "&"), changed
}

func removeJSONSessionKeys(value *any, path string, keys map[string]bool, changed *[]string) {
	switch current := (*value).(type) {
	case map[string]any:
		for key, child := range current {
			next := joinJSONPath(path, key)
			if keys[strings.ToLower(key)] {
				delete(current, key)
				*changed = append(*changed, "json:"+next)
				continue
			}
			removeJSONSessionKeys(&child, next, keys, changed)
			current[key] = child
		}
	case []any:
		for index, child := range current {
			next := fmt.Sprintf("%s[%d]", path, index)
			removeJSONSessionKeys(&child, next, keys, changed)
			current[index] = child
		}
	}
}

func invalidateJSONSessionKeys(value *any, path string, keys map[string]bool, invalidValue string, changed *[]string) {
	switch current := (*value).(type) {
	case map[string]any:
		for key, child := range current {
			next := joinJSONPath(path, key)
			if keys[strings.ToLower(key)] {
				current[key] = invalidValue
				*changed = append(*changed, "json:"+next)
				continue
			}
			invalidateJSONSessionKeys(&child, next, keys, invalidValue, changed)
			current[key] = child
		}
	case []any:
		for index, child := range current {
			next := fmt.Sprintf("%s[%d]", path, index)
			invalidateJSONSessionKeys(&child, next, keys, invalidValue, changed)
			current[index] = child
		}
	}
}

func joinJSONPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

func MutateMultipartFile(req *Request, filename, mimeType string, content []byte) (*Request, error) {
	return MutateMultipartFileAt(req, 0, filename, mimeType, content)
}

// MutateMultipartFileAt replaces one specific file part while preserving every
// other form field and file part. fileIndex follows Request.MultipartFiles.
func MutateMultipartFileAt(req *Request, fileIndex int, filename, mimeType string, content []byte) (*Request, error) {
	return mutateMultipartFileIdentityAt(req, fileIndex, "", filename, mimeType, content, true)
}

// MutateMultipartFileMetadataAt changes only filename and MIME while retaining
// the original file bytes. This matches a manual Burp extension-only test.
func MutateMultipartFileMetadataAt(req *Request, fileIndex int, filename, mimeType string) (*Request, error) {
	return mutateMultipartFileIdentityAt(req, fileIndex, "", filename, mimeType, nil, false)
}

// MutateMultipartFileIdentityAt also replaces the multipart field name. A few
// legacy Servlet upload handlers incorrectly use Content-Disposition "name"
// as the client filename. Modern handlers should use MutateMultipartFileAt;
// the upload plugin calls this compatibility path only after the standard
// filename-only probe fails and the original field name itself looks like a
// filename.
func MutateMultipartFileIdentityAt(req *Request, fileIndex int, fieldName, filename, mimeType string, content []byte) (*Request, error) {
	if strings.TrimSpace(fieldName) == "" {
		return nil, errorsf("multipart 文件字段名为空")
	}
	return mutateMultipartFileIdentityAt(req, fileIndex, fieldName, filename, mimeType, content, true)
}

// MutateMultipartFileIdentityMetadataAt is the legacy field-name compatibility
// form of MutateMultipartFileMetadataAt.
func MutateMultipartFileIdentityMetadataAt(req *Request, fileIndex int, fieldName, filename, mimeType string) (*Request, error) {
	if strings.TrimSpace(fieldName) == "" {
		return nil, errorsf("multipart 文件字段名为空")
	}
	return mutateMultipartFileIdentityAt(req, fileIndex, fieldName, filename, mimeType, nil, false)
}

func mutateMultipartFileIdentityAt(req *Request, fileIndex int, replacementFieldName, filename, mimeType string, content []byte, replaceContent bool) (*Request, error) {
	if fileIndex < 0 {
		return nil, errorsf("multipart 文件索引无效")
	}
	mediaType, params, err := mime.ParseMediaType(req.Header("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "multipart/form-data") || params["boundary"] == "" {
		return nil, errorsf("multipart boundary 无效")
	}
	reader := multipart.NewReader(bytes.NewReader(req.Body), params["boundary"])
	var rebuilt bytes.Buffer
	writer := multipart.NewWriter(&rebuilt)
	if err := writer.SetBoundary(params["boundary"]); err != nil {
		return nil, errorsf("multipart boundary 无效")
	}
	replaced := false
	currentFile := 0
	for {
		part, readErr := reader.NextPart()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, errorsf("multipart 报文解析失败")
		}
		header := part.Header
		isFile := part.FileName() != ""
		isTarget := isFile && currentFile == fileIndex
		if isFile {
			currentFile++
		}
		if isTarget {
			disposition, dispositionParams, parseErr := mime.ParseMediaType(header.Get("Content-Disposition"))
			if parseErr != nil {
				part.Close()
				return nil, errorsf("multipart 文件 Header 无效")
			}
			fieldName := dispositionParams["name"]
			if replacementFieldName != "" {
				fieldName = replacementFieldName
			}
			header.Set("Content-Disposition", disposition+`; name="`+escapeMultipartName(fieldName)+`"; filename="`+escapeMultipartName(filename)+`"`)
			header.Set("Content-Type", mimeType)
		}
		outputPart, createErr := writer.CreatePart(header)
		if createErr != nil {
			part.Close()
			return nil, createErr
		}
		if isTarget && replaceContent {
			if _, err := outputPart.Write(content); err != nil {
				part.Close()
				return nil, err
			}
			replaced = true
		} else {
			if _, err := io.Copy(outputPart, part); err != nil {
				part.Close()
				return nil, err
			}
			if isTarget {
				replaced = true
			}
		}
		part.Close()
	}
	if !replaced {
		return nil, fmt.Errorf("请求中未找到第 %d 个 multipart 文件字段", fileIndex+1)
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	out := req.Clone()
	out.Body = rebuilt.Bytes()
	return out, nil
}

func discoverPairs(location, raw string) []InsertionPoint {
	if raw == "" {
		return nil
	}
	counts := map[string]int{}
	var result []InsertionPoint
	for _, part := range strings.Split(raw, "&") {
		nameRaw, valueRaw, _ := strings.Cut(part, "=")
		name, err1 := url.QueryUnescape(nameRaw)
		value, err2 := url.QueryUnescape(valueRaw)
		if err1 != nil || err2 != nil || name == "" {
			continue
		}
		occurrence := counts[name]
		counts[name]++
		result = append(result, InsertionPoint{Location: location, Name: name, Path: name, Value: value, Occurrence: occurrence, ValueType: lexicalValueType(value)})
	}
	return result
}

func discoverMultipart(req *Request) []InsertionPoint {
	_, params, err := mime.ParseMediaType(req.Header("Content-Type"))
	if err != nil || params["boundary"] == "" {
		return nil
	}
	reader := multipart.NewReader(bytes.NewReader(req.Body), params["boundary"])
	var result []InsertionPoint
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return result
		}
		if part.FileName() != "" {
			result = append(result, InsertionPoint{Location: "multipart_filename", Name: part.FormName(), Path: part.FormName(), Value: part.FileName(), ValueType: "string"})
			_ = part.Close()
			continue
		}
		if part.FormName() == "" {
			_ = part.Close()
			continue
		}
		value, _ := io.ReadAll(io.LimitReader(part, 4097))
		_ = part.Close()
		if len(value) <= 4096 {
			text := string(value)
			result = append(result, InsertionPoint{Location: "multipart", Name: part.FormName(), Path: part.FormName(), Value: text, ValueType: lexicalValueType(text)})
		}
	}
	return result
}

func discoverPathSegments(req *Request) []InsertionPoint {
	u, err := url.Parse(req.Target)
	if err != nil {
		return nil
	}
	segments := strings.Split(strings.Trim(u.Path, "/"), "/")
	offset := 1
	var result []InsertionPoint
	uuidRE := regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f-]{27,}$`)
	for index, segment := range segments {
		value, _ := url.PathUnescape(segment)
		if isDigits(value) || uuidRE.MatchString(value) {
			result = append(result, InsertionPoint{Location: "path", Name: fmt.Sprintf("segment_%d", index+1), Path: strconv.Itoa(index + offset), Value: value, ValueType: "string"})
		}
	}
	return result
}

func discoverBusinessCookies(req *Request, sessions config.SessionKeyList) []InsertionPoint {
	sessionSet := sessionKeySet(sessions)
	var result []InsertionPoint
	for _, header := range req.Headers {
		if !strings.EqualFold(header.Name, "Cookie") {
			continue
		}
		for _, part := range strings.Split(header.Value, ";") {
			name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
			if ok && name != "" && !sessionSet[strings.ToLower(name)] {
				result = append(result, InsertionPoint{Location: "cookie", Name: name, Path: name, Value: value, ValueType: "string"})
			}
		}
	}
	return result
}

func isDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func decodePossibleBase64(value string) ([]byte, string) {
	for name, encoding := range map[string]*base64.Encoding{
		"std": base64.StdEncoding, "rawstd": base64.RawStdEncoding,
		"url": base64.URLEncoding, "rawurl": base64.RawURLEncoding,
	} {
		if decoded, err := encoding.DecodeString(value); err == nil && len(decoded) > 0 {
			return decoded, name
		}
	}
	return nil, ""
}

func mutateBase64JSON(req *Request, point InsertionPoint, value string) (*Request, error) {
	parts := strings.SplitN(point.Path, "|", 5)
	if len(parts) != 5 {
		return nil, errorsf("Base64 JSON 路径无效")
	}
	occurrence, _ := strconv.Atoi(parts[2])
	outer := InsertionPoint{Location: parts[0], Path: parts[1], Name: leafName(parts[1]), Occurrence: occurrence, ValueType: "string"}
	candidates := Discover(req, false)
	candidates = append(candidates, discoverBusinessCookies(req, nil)...)
	candidates = append(candidates, discoverPathSegments(req)...)
	for _, header := range req.Headers {
		if !strings.EqualFold(header.Name, "Host") && !strings.EqualFold(header.Name, "Content-Length") {
			candidates = append(candidates, InsertionPoint{Location: "header", Name: header.Name, Path: header.Name, Value: header.Value, ValueType: "string"})
		}
	}
	for _, candidate := range candidates {
		if candidate.Location == outer.Location && candidate.Path == outer.Path && candidate.Occurrence == outer.Occurrence {
			outer = candidate
			break
		}
	}
	decoded, encodingName := decodePossibleBase64(outer.Value)
	if encodingName == "" {
		return nil, errorsf("Base64 JSON 外层值无效")
	}
	var data any
	if decodeJSONAny(decoded, &data) != nil {
		return nil, errorsf("Base64 JSON 内容无效")
	}
	if err := setJSONPath(&data, parts[4], value); err != nil {
		return nil, err
	}
	encodedJSON, _ := json.Marshal(data)
	encodings := map[string]*base64.Encoding{"std": base64.StdEncoding, "rawstd": base64.RawStdEncoding, "url": base64.URLEncoding, "rawurl": base64.RawURLEncoding}
	encoder := encodings[parts[3]]
	if encoder == nil {
		return nil, errorsf("Base64 JSON 编码无效")
	}
	return Mutate(req, outer, encoder.EncodeToString(encodedJSON))
}

func replacePair(raw, key string, occurrence int, value string) string {
	seen := 0
	parts := strings.Split(raw, "&")
	for i, part := range parts {
		nameRaw, _, hasEqual := strings.Cut(part, "=")
		name, err := url.QueryUnescape(nameRaw)
		if err == nil && name == key {
			if seen == occurrence {
				encoded := url.QueryEscape(value)
				if hasEqual || value != "" {
					parts[i] = nameRaw + "=" + encoded
				} else {
					parts[i] = nameRaw
				}
				break
			}
			seen++
		}
	}
	return strings.Join(parts, "&")
}

func replacePairWithDuplicate(raw, key string, occurrence int, first, second string) string {
	seen := 0
	parts := strings.Split(raw, "&")
	for index, part := range parts {
		nameRaw, _, _ := strings.Cut(part, "=")
		name, err := url.QueryUnescape(nameRaw)
		if err != nil || name != key {
			continue
		}
		if seen == occurrence {
			parts[index] = nameRaw + "=" + url.QueryEscape(first) + "&" + nameRaw + "=" + url.QueryEscape(second)
			break
		}
		seen++
	}
	return strings.Join(parts, "&")
}

func replacePairNameValue(raw, key string, occurrence int, newName, newValue string) string {
	seen := 0
	parts := strings.Split(raw, "&")
	for i, part := range parts {
		nameRaw, _, _ := strings.Cut(part, "=")
		name, err := url.QueryUnescape(nameRaw)
		if err == nil && name == key {
			if seen == occurrence {
				parts[i] = url.QueryEscape(newName) + "=" + url.QueryEscape(newValue)
				break
			}
			seen++
		}
	}
	return strings.Join(parts, "&")
}

func walkJSON(value any, path string, points *[]InsertionPoint) {
	switch current := value.(type) {
	case map[string]any:
		for key, child := range current {
			next := key
			if path != "" {
				next = path + "." + key
			}
			walkJSON(child, next, points)
		}
	case []any:
		for index, child := range current {
			walkJSON(child, fmt.Sprintf("%s[%d]", path, index), points)
		}
	case nil:
		*points = append(*points, InsertionPoint{Location: "json", Name: leafName(path), Path: path, Value: "", ValueType: "null"})
	case string:
		*points = append(*points, InsertionPoint{Location: "json", Name: leafName(path), Path: path, Value: current, ValueType: "string"})
	case float64:
		*points = append(*points, InsertionPoint{Location: "json", Name: leafName(path), Path: path, Value: strconv.FormatFloat(current, 'f', -1, 64), ValueType: "number"})
	case json.Number:
		*points = append(*points, InsertionPoint{Location: "json", Name: leafName(path), Path: path, Value: current.String(), ValueType: "number"})
	case bool:
		*points = append(*points, InsertionPoint{Location: "json", Name: leafName(path), Path: path, Value: strconv.FormatBool(current), ValueType: "bool"})
	}
}

func setJSONPath(root *any, path string, value any) error {
	tokens := parsePath(path)
	if len(tokens) == 0 {
		return errorsf("JSON 路径为空")
	}
	return setJSONValue(root, tokens, value)
}

func setJSONValue(node *any, tokens []pathToken, value any) error {
	if len(tokens) == 0 {
		*node = value
		return nil
	}
	token := tokens[0]
	if token.index >= 0 {
		array, ok := (*node).([]any)
		if !ok || token.index >= len(array) {
			return errorsf("JSON 数组路径无效")
		}
		child := array[token.index]
		if err := setJSONValue(&child, tokens[1:], value); err != nil {
			return err
		}
		array[token.index] = child
		return nil
	}
	object, ok := (*node).(map[string]any)
	if !ok {
		return errorsf("JSON 对象路径无效")
	}
	child, ok := object[token.key]
	if !ok {
		return errorsf("JSON 字段不存在")
	}
	if err := setJSONValue(&child, tokens[1:], value); err != nil {
		return err
	}
	object[token.key] = child
	return nil
}

type pathToken struct {
	key   string
	index int
}

func parsePath(path string) []pathToken {
	re := regexp.MustCompile(`([^\.\[\]]+)|\[(\d+)\]`)
	var out []pathToken
	for _, match := range re.FindAllStringSubmatch(path, -1) {
		if match[2] != "" {
			value, _ := strconv.Atoi(match[2])
			out = append(out, pathToken{index: value})
		} else {
			out = append(out, pathToken{key: match[1], index: -1})
		}
	}
	return out
}

func coerceJSON(value, originalType string) any {
	if originalType == "bool" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	if originalType == "number" {
		if _, err := strconv.ParseFloat(value, 64); err == nil {
			return json.Number(value)
		}
	}
	return value
}

func decodeJSONAny(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errorsf("JSON 包含多个顶层值")
		}
		return err
	}
	return nil
}

func leafName(path string) string {
	parts := strings.Split(path, ".")
	leaf := parts[len(parts)-1]
	if at := strings.Index(leaf, "["); at >= 0 {
		leaf = leaf[:at]
	}
	return leaf
}

func dedupe(points []InsertionPoint) []InsertionPoint {
	seen := map[string]bool{}
	result := make([]InsertionPoint, 0, len(points))
	for _, point := range points {
		key := fmt.Sprintf("%s|%s|%d", point.Location, point.Path, point.Occurrence)
		for parent, depth := point.parent, 0; parent != nil && depth < 4; parent, depth = parent.parent, depth+1 {
			key += fmt.Sprintf("|parent:%s:%s:%d", parent.Location, parent.Path, parent.Occurrence)
		}
		if !seen[key] {
			seen[key] = true
			result = append(result, point)
		}
	}
	return result
}

func errorsf(message string) error { return fmt.Errorf("%s", message) }

func replaceNthStringFunc(re *regexp.Regexp, input string, occurrence int, mutate func(string) string) string {
	matches := re.FindAllStringIndex(input, -1)
	if occurrence < 0 || occurrence >= len(matches) {
		return input
	}
	match := matches[occurrence]
	return input[:match[0]] + mutate(input[match[0]:match[1]]) + input[match[1]:]
}
