package diff

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"html"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode"

	"jungle_happy_Scan/internal/config"
	"jungle_happy_Scan/internal/model"
)

var whitespace = regexp.MustCompile(`\s+`)
var (
	htmlComment = regexp.MustCompile(`(?is)<!--.*?-->`)
	styleBlock  = regexp.MustCompile(`(?is)<style\b[^>]*>.*?</style\s*>`)
	htmlTag     = regexp.MustCompile(`(?is)<[^>]{1,1000}>`)
	hiddenValue = regexp.MustCompile(`(?is)(<input\b[^>]*\btype\s*=\s*["']?hidden["']?[^>]*\bvalue\s*=\s*["'])[^"']*(["'])`)
)

const (
	maxCachedRegexps       = 256
	maxNormalizedResponses = 512
)

type regexpCache struct {
	mu    sync.RWMutex
	items map[string]*regexp.Regexp
	order []string
}

var compiledRegexps = regexpCache{items: make(map[string]*regexp.Regexp)}

func cachedRegexp(pattern string) (*regexp.Regexp, error) {
	compiledRegexps.mu.RLock()
	if expression := compiledRegexps.items[pattern]; expression != nil {
		compiledRegexps.mu.RUnlock()
		return expression, nil
	}
	compiledRegexps.mu.RUnlock()
	expression, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	compiledRegexps.mu.Lock()
	defer compiledRegexps.mu.Unlock()
	if existing := compiledRegexps.items[pattern]; existing != nil {
		return existing, nil
	}
	if len(compiledRegexps.order) >= maxCachedRegexps {
		oldest := compiledRegexps.order[0]
		compiledRegexps.order = compiledRegexps.order[1:]
		delete(compiledRegexps.items, oldest)
	}
	compiledRegexps.items[pattern] = expression
	compiledRegexps.order = append(compiledRegexps.order, pattern)
	return expression, nil
}

type normalizationCache struct {
	mu    sync.RWMutex
	items map[[sha256.Size]byte]normalizedFingerprint
	order [][sha256.Size]byte
}

type normalizedFingerprint struct {
	text     string
	shingles map[string]int
}

type responseFingerprint struct {
	statusCode int
	bodyLength int
	truncated  bool
	normalized normalizedFingerprint
}

var normalizedResponses = normalizationCache{items: make(map[[sha256.Size]byte]normalizedFingerprint)}

func Normalize(response model.Response, cfg config.Config) string {
	return fingerprint(response, cfg).normalized.text
}

func fingerprint(response model.Response, cfg config.Config) responseFingerprint {
	text := sampleSegments(response.Body, 500_000)
	key := normalizationCacheKey(response.Headers["content-type"], cfg.DynamicPatterns, text)
	normalizedResponses.mu.RLock()
	if cached, ok := normalizedResponses.items[key]; ok {
		normalizedResponses.mu.RUnlock()
		return responseFingerprint{
			statusCode: response.StatusCode,
			bodyLength: responseLength(response),
			truncated:  response.Truncated,
			normalized: cached,
		}
	}
	normalizedResponses.mu.RUnlock()

	text = normalizeSample(response, cfg, text)
	normalized := normalizedFingerprint{text: text, shingles: shingles(text)}
	normalizedResponses.mu.Lock()
	if existing, exists := normalizedResponses.items[key]; exists {
		normalized = existing
	} else {
		if len(normalizedResponses.order) >= maxNormalizedResponses {
			oldest := normalizedResponses.order[0]
			normalizedResponses.order = normalizedResponses.order[1:]
			delete(normalizedResponses.items, oldest)
		}
		normalizedResponses.items[key] = normalized
		normalizedResponses.order = append(normalizedResponses.order, key)
	}
	normalizedResponses.mu.Unlock()
	return responseFingerprint{
		statusCode: response.StatusCode,
		bodyLength: responseLength(response),
		truncated:  response.Truncated,
		normalized: normalized,
	}
}

func responseLength(response model.Response) int {
	if response.RawBytes > int64(len(response.Body)) && response.RawBytes <= int64(^uint(0)>>1) {
		return int(response.RawBytes)
	}
	return len(response.Body)
}

func normalizeSample(response model.Response, cfg config.Config, text string) string {
	if looksLikeJSON(response, text) {
		var value any
		decoder := json.NewDecoder(strings.NewReader(text))
		decoder.UseNumber()
		if decoder.Decode(&value) == nil {
			stripDynamicKeys(value)
			if encoded, err := json.Marshal(value); err == nil {
				text = string(encoded)
			}
		}
	}
	if looksLikeHTML(response, text) {
		text = htmlComment.ReplaceAllString(text, " ")
		// CSS has no business outcome, but inline JavaScript in legacy JSP pages
		// often carries the actual result rows/status. Preserve script content
		// and let configured dynamic patterns remove only known volatile values.
		text = styleBlock.ReplaceAllString(text, " ")
		text = hiddenValue.ReplaceAllString(text, `${1}<dynamic>${2}`)
		text = htmlTag.ReplaceAllString(text, " ")
		text = html.UnescapeString(text)
	}
	for _, pattern := range cfg.DynamicPatterns {
		if re, err := cachedRegexp(pattern); err == nil {
			text = re.ReplaceAllString(text, "<dynamic>")
		}
	}
	return strings.TrimSpace(whitespace.ReplaceAllString(text, " "))
}

func looksLikeJSON(response model.Response, text string) bool {
	contentType := strings.ToLower(response.Headers["content-type"])
	if strings.Contains(contentType, "application/json") || strings.Contains(contentType, "+json") {
		return true
	}
	trimmed := strings.TrimSpace(text)
	return len(trimmed) > 1 && (trimmed[0] == '{' || trimmed[0] == '[') && json.Valid([]byte(trimmed))
}

func normalizationCacheKey(contentType string, patterns []string, sample string) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte(strings.ToLower(contentType)))
	_, _ = hash.Write([]byte{0})
	for _, pattern := range patterns {
		_, _ = hash.Write([]byte(pattern))
		_, _ = hash.Write([]byte{0})
	}
	_, _ = hash.Write([]byte(sample))
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

// sampleSegments prevents a long JSP/HTML response from making comparison
// unbounded while still retaining the beginning, middle and end. V1 only read
// the first 500 KB, which could miss business data rendered near the page tail.
func sampleSegments(body []byte, limit int) string {
	if len(body) <= limit {
		return string(body)
	}
	head := limit / 2
	middle := limit / 5
	tail := limit - head - middle
	middleStart := len(body)/2 - middle/2
	var out bytes.Buffer
	out.Grow(limit + 64)
	out.Write(body[:head])
	out.WriteString(" <jhs-segment> ")
	out.Write(body[middleStart : middleStart+middle])
	out.WriteString(" <jhs-segment> ")
	out.Write(body[len(body)-tail:])
	return out.String()
}

func looksLikeHTML(response model.Response, text string) bool {
	contentType := strings.ToLower(response.Headers["content-type"])
	if strings.Contains(contentType, "html") || strings.Contains(contentType, "x-jsp") {
		return true
	}
	prefix := strings.ToLower(strings.TrimSpace(text))
	return strings.HasPrefix(prefix, "<!doctype html") || strings.HasPrefix(prefix, "<html")
}

func Similarity(left, right model.Response, cfg config.Config) float64 {
	if left.StatusCode != right.StatusCode && (left.StatusCode/100) != (right.StatusCode/100) {
		return 0
	}
	if bytes.Equal(left.Body, right.Body) && responseLength(left) == responseLength(right) && left.Truncated == right.Truncated {
		return 1
	}
	return fingerprintSimilarity(fingerprint(left, cfg), fingerprint(right, cfg))
}

func normalizedSimilarity(a, b string) float64 {
	return fingerprintSimilarity(
		responseFingerprint{bodyLength: len(a), normalized: normalizedFingerprint{text: a, shingles: shingles(a)}},
		responseFingerprint{bodyLength: len(b), normalized: normalizedFingerprint{text: b, shingles: shingles(b)}},
	)
}

func fingerprintSimilarity(left, right responseFingerprint) float64 {
	if left.statusCode != right.statusCode && left.statusCode/100 != right.statusCode/100 {
		return 0
	}
	a, b := left.normalized.text, right.normalized.text
	if a == b {
		score := 0.85 + ratio(min(left.bodyLength, right.bodyLength), max(left.bodyLength, right.bodyLength))*0.15
		if left.truncated != right.truncated {
			score *= 0.98
		}
		return score
	}
	if a == "" || b == "" {
		return 0
	}
	leftSet, rightSet := left.normalized.shingles, right.normalized.shingles
	setIntersection := 0
	multisetIntersection := 0
	multisetUnion := 0
	for token, leftCount := range leftSet {
		if rightCount := rightSet[token]; rightCount > 0 {
			setIntersection++
			multisetIntersection += min(leftCount, rightCount)
			multisetUnion += max(leftCount, rightCount)
		} else {
			multisetUnion += leftCount
		}
	}
	for token, rightCount := range rightSet {
		if leftSet[token] == 0 {
			multisetUnion += rightCount
		}
	}
	setUnion := len(leftSet) + len(rightSet) - setIntersection
	setJaccard := ratio(setIntersection, setUnion)
	multisetJaccard := ratio(multisetIntersection, multisetUnion)
	normalizedLengthRatio := ratio(min(len(a), len(b)), max(len(a), len(b)))
	bodyLengthRatio := ratio(min(left.bodyLength, right.bodyLength), max(left.bodyLength, right.bodyLength))
	// Set overlap remains sensitive to a small novel SQL/JDBC error block in a
	// large page, while multiset overlap and lengths preserve repeated row/count
	// information that a plain set-based Jaccard comparison discards.
	score := setJaccard*0.50 + multisetJaccard*0.30 + normalizedLengthRatio*0.15 + bodyLengthRatio*0.05
	if left.truncated != right.truncated {
		score *= 0.98
	}
	return math.Min(1, score)
}

func ratio(numerator, denominator int) float64 {
	if denominator <= 0 {
		return 1
	}
	return float64(numerator) / float64(denominator)
}

func BaselineStability(responses []model.Response, cfg config.Config) float64 {
	if len(responses) < 2 {
		return 1
	}
	fingerprints := make([]responseFingerprint, len(responses))
	for index, response := range responses {
		fingerprints[index] = fingerprint(response, cfg)
	}
	total := 0.0
	count := 0
	for i := 0; i < len(responses); i++ {
		for j := i + 1; j < len(responses); j++ {
			total += fingerprintSimilarity(fingerprints[i], fingerprints[j])
			count++
		}
	}
	return total / float64(count)
}

// RepresentativeBaselineIndex returns the medoid response: the sample with
// the greatest similarity to all other baseline samples. This avoids making a
// transient gateway error or one unusually dynamic response the oracle for
// every active plugin. Ties prefer the newest sample.
func RepresentativeBaselineIndex(responses []model.Response, cfg config.Config) int {
	if len(responses) < 2 {
		return 0
	}
	fingerprints := make([]responseFingerprint, len(responses))
	for index, response := range responses {
		fingerprints[index] = fingerprint(response, cfg)
	}
	bestIndex := 0
	bestScore := -1.0
	for index := range fingerprints {
		score := 0.0
		for other := range fingerprints {
			if index != other {
				score += fingerprintSimilarity(fingerprints[index], fingerprints[other])
			}
		}
		if score >= bestScore {
			bestIndex, bestScore = index, score
		}
	}
	return bestIndex
}

func LikelyAuthDenied(response model.Response, cfg config.Config) bool {
	if response.StatusCode == 401 || response.StatusCode == 403 {
		return true
	}
	text := strings.ToLower(string(response.Body))
	if len(text) > 100_000 {
		text = text[:100_000]
	}
	for _, pattern := range cfg.DeniedPatterns {
		if re, err := cachedRegexp("(?i)" + pattern); err == nil && re.MatchString(text) {
			return true
		}
	}
	return false
}

func LikelySuccess(response model.Response, cfg config.Config) bool {
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return false
	}
	text := string(response.Body)
	for _, pattern := range cfg.SuccessPatterns {
		if re, err := cachedRegexp("(?i)" + pattern); err == nil && re.MatchString(text) {
			return true
		}
	}
	return response.StatusCode >= 200 && response.StatusCode < 300 && !LikelyAuthDenied(response, cfg)
}

func Excerpt(text, marker string, width int) string {
	compact := whitespace.ReplaceAllString(text, " ")
	if width <= 0 {
		width = 400
	}
	start := 0
	if marker != "" {
		at := strings.Index(strings.ToLower(compact), strings.ToLower(marker))
		if at >= 0 {
			start = max(0, at-width/3)
		}
	}
	end := min(len(compact), start+width)
	return compact[start:end]
}

func shingles(text string) map[string]int {
	words := strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return unicode.IsSpace(r) || strings.ContainsRune(`,;:{}[]()<>"'=/\\`, r)
	})
	if len(words) == 0 {
		return map[string]int{text: 1}
	}
	if len(words) < 3 {
		return map[string]int{strings.Join(words, " "): 1}
	}
	set := make(map[string]int, len(words))
	for i := 0; i+2 < len(words); i++ {
		set[strings.Join(words[i:i+3], " ")]++
	}
	return set
}

func stripDynamicKeys(value any) {
	switch current := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(current))
		for key := range current {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			lower := strings.ToLower(key)
			if lower == "timestamp" || lower == "time" || lower == "requestid" || lower == "traceid" || lower == "nonce" {
				current[key] = "<dynamic>"
				continue
			}
			stripDynamicKeys(current[key])
		}
	case []any:
		for _, child := range current {
			stripDynamicKeys(child)
		}
	}
}
