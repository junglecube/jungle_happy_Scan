package httpraw

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/model"
)

const maxTransformRegexps = 256

var transformRegexps = struct {
	sync.RWMutex
	items map[string]*regexp.Regexp
	order []string
}{items: make(map[string]*regexp.Regexp)}

func cachedTransformRegexp(pattern string) (*regexp.Regexp, error) {
	transformRegexps.RLock()
	if expression := transformRegexps.items[pattern]; expression != nil {
		transformRegexps.RUnlock()
		return expression, nil
	}
	transformRegexps.RUnlock()
	expression, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	transformRegexps.Lock()
	defer transformRegexps.Unlock()
	if existing := transformRegexps.items[pattern]; existing != nil {
		return existing, nil
	}
	if len(transformRegexps.order) >= maxTransformRegexps {
		oldest := transformRegexps.order[0]
		transformRegexps.order = transformRegexps.order[1:]
		delete(transformRegexps.items, oldest)
	}
	transformRegexps.items[pattern] = expression
	transformRegexps.order = append(transformRegexps.order, pattern)
	return expression, nil
}

func ApplyRequestTransforms(request *Request, rules []config.RequestTransform) (*Request, error) {
	out := request.Clone()
	for _, rule := range rules {
		source := transformSource(out, rule.Source)
		var value string
		switch rule.Algorithm {
		case "timestamp":
			value = strconv.FormatInt(time.Now().Unix(), 10)
		case "uuid":
			value = randomUUID()
		case "regex_replace":
			re, err := cachedTransformRegexp(rule.Pattern)
			if err != nil {
				return nil, err
			}
			value = re.ReplaceAllString(source, rule.Replacement)
		case "sha256":
			sum := sha256.Sum256([]byte(source))
			value = encodeDigest(sum[:], rule.Encoding)
		case "hmac-sha256":
			mac := hmac.New(sha256.New, []byte(rule.Secret))
			_, _ = mac.Write([]byte(source))
			value = encodeDigest(mac.Sum(nil), rule.Encoding)
		case "base64":
			value = base64.StdEncoding.EncodeToString([]byte(source))
		default:
			return nil, fmt.Errorf("不支持动态算法 %q", rule.Algorithm)
		}
		var err error
		out, err = applyDestination(out, rule.Destination, value)
		if err != nil {
			return nil, fmt.Errorf("动态规则 %q: %w", rule.Name, err)
		}
	}
	return out, nil
}

func ApplyResponseExtractors(request *Request, response model.Response, rules []config.ResponseExtractor) (*Request, []string) {
	out := request.Clone()
	var applied []string
	for destination, value := range ExtractResponseValues(response, rules) {
		next, err := applyDestination(out, destination, value)
		if err != nil {
			continue
		}
		out = next
		applied = append(applied, extractorNameForDestination(rules, destination))
	}
	return out, applied
}

// ExtractResponseValues and ApplyDestinationValues form the rotating-session
// pipeline. The engine reapplies the latest CSRF/session value before every
// request and refreshes it after every response.
func ExtractResponseValues(response model.Response, rules []config.ResponseExtractor) map[string]string {
	values := make(map[string]string)
	for _, rule := range rules {
		source := response.Text()
		if strings.HasPrefix(strings.ToLower(rule.Source), "header:") {
			source = strings.Join(response.HeaderAll(strings.TrimSpace(rule.Source[len("header:"):])), "\n")
		}
		re, err := cachedTransformRegexp(rule.Pattern)
		if err != nil {
			continue
		}
		match := re.FindStringSubmatch(source)
		if len(match) == 0 {
			continue
		}
		value := match[0]
		if len(match) > 1 {
			value = match[1]
		}
		values[rule.Destination] = value
	}
	return values
}

func ApplyDestinationValues(request *Request, values map[string]string) (*Request, error) {
	out := request.Clone()
	for destination, value := range values {
		var err error
		out, err = applyDestination(out, destination, value)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func extractorNameForDestination(rules []config.ResponseExtractor, destination string) string {
	for _, rule := range rules {
		if rule.Destination == destination {
			return rule.Name
		}
	}
	return destination
}

func transformSource(request *Request, source string) string {
	switch {
	case source == "" || source == "body":
		return string(request.Body)
	case source == "target":
		return request.Target
	case strings.HasPrefix(strings.ToLower(source), "header:"):
		return request.Header(strings.TrimSpace(source[len("header:"):]))
	case strings.HasPrefix(strings.ToLower(source), "literal:"):
		return source[len("literal:"):]
	default:
		return source
	}
}

func applyDestination(request *Request, destination, value string) (*Request, error) {
	switch {
	case strings.HasPrefix(strings.ToLower(destination), "header:"):
		return request.WithHeader(strings.TrimSpace(destination[len("header:"):]), value), nil
	case strings.HasPrefix(strings.ToLower(destination), "query:"):
		name := strings.TrimSpace(destination[len("query:"):])
		out := request.Clone()
		u, err := url.Parse(out.Target)
		if err != nil {
			return nil, err
		}
		for _, point := range discoverPairs("query", u.RawQuery) {
			if point.Name == name {
				u.RawQuery = replacePair(u.RawQuery, point.Name, point.Occurrence, value)
				out.Target = u.String()
				return out, nil
			}
		}
		if u.RawQuery == "" {
			u.RawQuery = url.QueryEscape(name) + "=" + url.QueryEscape(value)
		} else {
			u.RawQuery += "&" + url.QueryEscape(name) + "=" + url.QueryEscape(value)
		}
		out.Target = u.String()
		return out, nil
	case strings.HasPrefix(strings.ToLower(destination), "json:"):
		path := strings.TrimSpace(destination[len("json:"):])
		points, err := discoverJSONPoints(request.Body)
		if err != nil {
			return nil, err
		}
		for _, point := range points {
			if point.Path != path {
				continue
			}
			replacement, _ := json.Marshal(value)
			body, replaceErr := replaceJSONPoint(request.Body, point, replacement)
			if replaceErr != nil {
				return nil, replaceErr
			}
			return request.WithBody(body), nil
		}
		return nil, fmt.Errorf("JSON 路径 %q 不存在", path)
	case strings.HasPrefix(strings.ToLower(destination), "cookie:"):
		name := strings.TrimSpace(destination[len("cookie:"):])
		return request.WithHeader("Cookie", replaceCookieValue(request.Header("Cookie"), name, value)), nil
	case strings.HasPrefix(strings.ToLower(destination), "form:"):
		name := strings.TrimSpace(destination[len("form:"):])
		if !strings.Contains(request.ContentType(), "application/x-www-form-urlencoded") {
			return nil, fmt.Errorf("请求体不是 form-urlencoded")
		}
		for _, point := range discoverPairs("form", string(request.Body)) {
			if point.Name == name {
				return request.WithBody([]byte(replacePair(string(request.Body), point.Name, point.Occurrence, value))), nil
			}
		}
		return AddParameter(request, "form", name, value)
	case strings.HasPrefix(strings.ToLower(destination), "multipart:"):
		name := strings.TrimSpace(destination[len("multipart:"):])
		for _, point := range discoverMultipart(request) {
			if point.Location == "multipart" && point.Name == name {
				return Mutate(request, point, value)
			}
		}
		return AddParameter(request, "multipart", name, value)
	case destination == "body":
		return request.WithBody([]byte(value)), nil
	default:
		return nil, fmt.Errorf("不支持目标 %q", destination)
	}
}

func replaceCookieValue(raw, name, value string) string {
	parts := strings.Split(raw, ";")
	for index, part := range parts {
		key, _, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(key, name) {
			prefix := ""
			if index > 0 {
				prefix = " "
			}
			parts[index] = prefix + key + "=" + value
			return strings.Join(parts, ";")
		}
	}
	if strings.TrimSpace(raw) == "" {
		return name + "=" + value
	}
	return raw + "; " + name + "=" + value
}

func encodeDigest(value []byte, encoding string) string {
	if strings.EqualFold(encoding, "base64") {
		return base64.StdEncoding.EncodeToString(value)
	}
	return hex.EncodeToString(value)
}

func randomUUID() string {
	value := make([]byte, 16)
	_, _ = rand.Read(value)
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", value[:4], value[4:6], value[6:8], value[8:10], value[10:])
}
