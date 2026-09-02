package httpraw

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var (
	methodPattern = regexp.MustCompile(`^[A-Z!#$%&'*+.^_\x60|~-]+$`)
	headerPattern = regexp.MustCompile(`^[!#$%&'*+.^_\x60|~0-9A-Za-z-]+$`)
	secretBody    = regexp.MustCompile(`(?i)("(?:password|passwd|pwd|token|secret|session(?:id)?|authorization|api[_-]?key)"\s*:\s*")[^"]*(")`)
)

var hopByHop = map[string]bool{
	"connection": true, "proxy-connection": true, "keep-alive": true,
	"transfer-encoding": true, "upgrade": true, "content-length": true,
	"host": true, "accept-encoding": true,
}

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Request struct {
	Method      string   `json:"method"`
	Target      string   `json:"target"`
	HTTPVersion string   `json:"http_version"`
	Headers     []Header `json:"headers"`
	Body        []byte   `json:"-"`
	Scheme      string   `json:"scheme"`
}

func Parse(raw, defaultScheme string) (*Request, error) {
	return ParseWithLimit(raw, defaultScheme, 5_000_000)
}

// ParseWithLimit is used by the interactive proxy editor, whose bounded
// interception buffer is intentionally larger than the pasted-request API.
func ParseWithLimit(raw, defaultScheme string, limit int) (*Request, error) {
	if limit <= 0 {
		limit = 5_000_000
	}
	if len(raw) > limit {
		return nil, fmt.Errorf("HTTP 报文超过 %d 字节限制", limit)
	}
	head, body, found := splitRawRequest(raw)
	head = strings.ReplaceAll(head, "\r\n", "\n")
	lines := strings.Split(head, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return nil, errors.New("缺少 HTTP 请求行")
	}
	parts := strings.Fields(lines[0])
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/") {
		return nil, errors.New("请求行格式应为 METHOD TARGET HTTP/x.y")
	}
	if !methodPattern.MatchString(parts[0]) {
		return nil, errors.New("HTTP 方法不合法")
	}
	req := &Request{Method: parts[0], Target: parts[1], HTTPVersion: parts[2], Scheme: defaultScheme}
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) && len(req.Headers) > 0 {
			i := len(req.Headers) - 1
			req.Headers[i].Value += " " + strings.TrimSpace(line)
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok || !headerPattern.MatchString(name) {
			return nil, fmt.Errorf("HTTP Header 不合法: %q", line)
		}
		req.Headers = append(req.Headers, Header{Name: name, Value: strings.TrimSpace(value)})
	}
	if found {
		req.Body = []byte(body)
		req.Body = normalizePastedMultipart(req.Header("Content-Type"), req.Body)
	}
	if parsed, err := url.Parse(req.Target); err == nil && parsed.IsAbs() {
		req.Scheme = parsed.Scheme
	}
	if req.Host() == "" {
		return nil, errors.New("HTTP 报文必须包含 Host Header 或绝对 URL")
	}
	return req, nil
}

// splitRawRequest normalizes only the HTTP header block. The body must remain
// byte-for-byte intact: replacing CRLF globally corrupts multipart framing and
// can also alter uploaded file content.
func splitRawRequest(raw string) (head, body string, found bool) {
	crlfIndex := strings.Index(raw, "\r\n\r\n")
	lfIndex := strings.Index(raw, "\n\n")
	switch {
	case crlfIndex >= 0 && (lfIndex < 0 || crlfIndex <= lfIndex):
		return raw[:crlfIndex], raw[crlfIndex+4:], true
	case lfIndex >= 0:
		return raw[:lfIndex], raw[lfIndex+2:], true
	}
	return raw, "", false
}

// Browsers normalize pasted textarea line endings to LF. Spring/Tomcat and
// some gateways require RFC-compliant CRLF multipart delimiters. Re-serialize
// only LF-framed multipart bodies; already-valid Burp/API bodies are preserved.
func normalizePastedMultipart(contentType string, body []byte) []byte {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.EqualFold(mediaType, "multipart/form-data") || params["boundary"] == "" {
		return body
	}
	boundary := params["boundary"]
	firstMarker := []byte("--" + boundary)
	index := bytes.Index(body, firstMarker)
	if index < 0 {
		return body
	}
	lineEnd := index + len(firstMarker)
	if len(body) >= lineEnd+2 && bytes.Equal(body[lineEnd:lineEnd+2], []byte("\r\n")) {
		return body
	}
	if len(body) <= lineEnd || body[lineEnd] != '\n' {
		return body
	}

	reader := multipart.NewReader(bytes.NewReader(body), boundary)
	var rebuilt bytes.Buffer
	writer := multipart.NewWriter(&rebuilt)
	if err := writer.SetBoundary(boundary); err != nil {
		return body
	}
	parts := 0
	for {
		part, readErr := reader.NextRawPart()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return body
		}
		target, createErr := writer.CreatePart(part.Header)
		if createErr != nil {
			_ = part.Close()
			return body
		}
		if _, copyErr := io.Copy(target, part); copyErr != nil {
			_ = part.Close()
			return body
		}
		_ = part.Close()
		parts++
	}
	if parts == 0 || writer.Close() != nil {
		return body
	}
	return rebuilt.Bytes()
}

func (r *Request) Clone() *Request {
	out := *r
	out.Headers = append([]Header(nil), r.Headers...)
	out.Body = append([]byte(nil), r.Body...)
	return &out
}

func (r *Request) Header(name string) string {
	for i := len(r.Headers) - 1; i >= 0; i-- {
		if strings.EqualFold(r.Headers[i].Name, name) {
			return r.Headers[i].Value
		}
	}
	return ""
}

func (r *Request) WithHeader(name, value string) *Request {
	out := r.Clone()
	filtered := out.Headers[:0]
	for _, h := range out.Headers {
		if !strings.EqualFold(h.Name, name) {
			filtered = append(filtered, h)
		}
	}
	out.Headers = append(filtered, Header{Name: name, Value: value})
	return out
}

func (r *Request) WithoutHeaders(names ...string) *Request {
	out := r.Clone()
	filtered := out.Headers[:0]
	for _, h := range out.Headers {
		remove := false
		for _, name := range names {
			if strings.EqualFold(h.Name, name) {
				remove = true
				break
			}
		}
		if !remove {
			filtered = append(filtered, h)
		}
	}
	out.Headers = filtered
	return out
}

func (r *Request) WithBody(body []byte) *Request {
	out := r.Clone()
	out.Body = append([]byte(nil), body...)
	return out
}

func (r *Request) WithScheme(scheme string) *Request {
	out := r.Clone()
	out.Scheme = scheme
	if parsed, err := url.Parse(out.Target); err == nil && parsed.IsAbs() {
		parsed.Scheme = scheme
		out.Target = parsed.String()
	}
	return out
}

func (r *Request) Host() string {
	if u, err := url.Parse(r.Target); err == nil && u.Hostname() != "" {
		return strings.ToLower(u.Hostname())
	}
	host := r.Header("Host")
	if u, err := url.Parse("//" + host); err == nil {
		return strings.ToLower(u.Hostname())
	}
	return ""
}

func (r *Request) Authority() string {
	if u, err := url.Parse(r.Target); err == nil && u.Host != "" {
		return u.Host
	}
	return r.Header("Host")
}

func (r *Request) URL() (string, error) {
	u, err := url.Parse(r.Target)
	if err != nil {
		return "", err
	}
	if u.IsAbs() {
		return u.String(), nil
	}
	target := r.Target
	if !strings.HasPrefix(target, "/") {
		target = "/" + target
	}
	return r.Scheme + "://" + r.Authority() + target, nil
}

func (r *Request) ContentType() string { return strings.ToLower(r.Header("Content-Type")) }

func (r *Request) TransportHeaders() http.Header {
	h := make(http.Header)
	for _, item := range r.Headers {
		if !hopByHop[strings.ToLower(item.Name)] {
			h.Add(item.Name, item.Value)
		}
	}
	return h
}

func (r *Request) Raw(redact bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %s\r\n", r.Method, r.Target, r.HTTPVersion)
	for _, h := range r.Headers {
		value := h.Value
		if redact && isSensitiveHeader(h.Name) {
			value = "<redacted>"
		}
		fmt.Fprintf(&b, "%s: %s\r\n", h.Name, value)
	}
	b.WriteString("\r\n")
	body := string(r.Body)
	if redact {
		body = secretBody.ReplaceAllString(body, `$1<redacted>$2`)
	}
	if len(body) > 4000 {
		body = body[:4000] + "\n...[truncated]"
	}
	b.WriteString(body)
	return b.String()
}

func (r *Request) ReplaceTarget(path string) *Request {
	out := r.Clone()
	out.Method = http.MethodGet
	out.Target = path
	out.Body = nil
	out = out.WithoutHeaders("Content-Type", "Content-Length")
	return out
}

func (r *Request) FirstMultipartFile() (filename string, ok bool) {
	files := r.MultipartFiles()
	if len(files) == 0 {
		return "", false
	}
	return files[0].Filename, true
}

type MultipartFile struct {
	Index       int    `json:"index"`
	FieldName   string `json:"field_name"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type,omitempty"`
}

// MultipartFiles enumerates every uploaded file part in wire order. Index is
// the file-part index (not the index of ordinary text parts) and can be passed
// to MutateMultipartFileAt.
func (r *Request) MultipartFiles() []MultipartFile {
	mediaType, params, err := mime.ParseMediaType(r.Header("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "multipart/form-data") || params["boundary"] == "" {
		return nil
	}
	reader := multipart.NewReader(bytes.NewReader(r.Body), params["boundary"])
	var files []MultipartFile
	for {
		part, readErr := reader.NextPart()
		if readErr == io.EOF {
			return files
		}
		if readErr != nil {
			return nil
		}
		if part.FileName() != "" {
			files = append(files, MultipartFile{
				Index: len(files), FieldName: part.FormName(), Filename: part.FileName(),
				ContentType: part.Header.Get("Content-Type"),
			})
		}
		_ = part.Close()
	}
}

func isSensitiveHeader(name string) bool {
	switch strings.ToLower(name) {
	case "authorization", "proxy-authorization", "cookie", "x-api-key", "token", "x-auth-token":
		return true
	default:
		return false
	}
}
