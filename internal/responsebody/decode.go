package responsebody

import (
	"bytes"
	"mime"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

var htmlCharset = regexp.MustCompile(`(?i)<meta[^>]+charset\s*=\s*["']?\s*([a-z0-9._-]+)`)

// Decode converts common legacy Chinese servlet/JSP response encodings to
// UTF-8. The original bytes are still accounted for by Response.RawBytes; all
// plugin matching and evidence rendering use this decoded representation.
func Decode(body []byte, contentType string) ([]byte, string) {
	charset := headerCharset(contentType)
	if charset == "" && looksLikeHTML(contentType, body) {
		if match := htmlCharset.FindSubmatch(head(body, 8192)); len(match) == 2 {
			charset = normalizeCharset(string(match[1]))
		}
	}
	if charset == "" || charset == "utf-8" || charset == "utf8" {
		if utf8.Valid(body) {
			return body, "utf-8"
		}
		if charset == "" && !looksTextual(contentType, body) {
			return body, "binary"
		}
		// Old Java pages frequently omit charset while serving GBK. Only use
		// the fallback when the payload is not already valid UTF-8.
		charset = "gb18030"
	}
	var transformer transform.Transformer
	switch normalizeCharset(charset) {
	case "gbk", "gb2312", "x-gbk":
		transformer = simplifiedchinese.GBK.NewDecoder()
		charset = "gbk"
	case "gb18030":
		transformer = simplifiedchinese.GB18030.NewDecoder()
	default:
		return body, normalizeCharset(charset)
	}
	decoded, _, err := transform.Bytes(transformer, body)
	if err != nil || !utf8.Valid(decoded) {
		return body, normalizeCharset(charset)
	}
	return decoded, normalizeCharset(charset)
}

func looksTextual(contentType string, body []byte) bool {
	lower := strings.ToLower(contentType)
	for _, marker := range []string{"text/", "json", "xml", "javascript", "x-www-form-urlencoded", "x-jsp"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return looksLikeHTML(contentType, body)
}

func headerCharset(contentType string) string {
	_, params, err := mime.ParseMediaType(contentType)
	if err == nil {
		return normalizeCharset(params["charset"])
	}
	return ""
}

func looksLikeHTML(contentType string, body []byte) bool {
	lower := strings.ToLower(contentType)
	if strings.Contains(lower, "html") || strings.Contains(lower, "x-jsp") {
		return true
	}
	prefix := strings.ToLower(string(bytes.TrimSpace(head(body, 512))))
	return strings.HasPrefix(prefix, "<!doctype html") || strings.HasPrefix(prefix, "<html")
}

func normalizeCharset(value string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(value), `"'`))
}

func head(body []byte, size int) []byte {
	if len(body) <= size {
		return body
	}
	return body[:size]
}
