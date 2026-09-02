package responsebody

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"strings"
)

// DecodeContentEncoding decodes HTTP content codings into a bounded semantic
// body. The caller remains responsible for retaining the original wire bytes
// when they still need to be forwarded to a browser.
func DecodeContentEncoding(body []byte, contentEncoding string, limit int) ([]byte, bool, bool, error) {
	encodings := contentEncodings(contentEncoding)
	if len(encodings) == 0 {
		return body, false, false, nil
	}
	for _, encoding := range encodings {
		if encoding != "gzip" && encoding != "x-gzip" && encoding != "deflate" && encoding != "identity" {
			return body, false, false, fmt.Errorf("unsupported content-encoding %q", encoding)
		}
	}
	decoded := append([]byte(nil), body...)
	truncated := false
	applied := false
	for index := len(encodings) - 1; index >= 0; index-- {
		encoding := encodings[index]
		if encoding == "identity" {
			continue
		}
		var (
			next     []byte
			stageCut bool
			err      error
		)
		switch encoding {
		case "gzip", "x-gzip":
			next, stageCut, err = decodeGzip(decoded, limit)
		case "deflate":
			next, stageCut, err = decodeDeflate(decoded, limit)
		}
		if err != nil {
			return body, false, false, err
		}
		decoded, truncated, applied = next, truncated || stageCut, true
	}
	return decoded, applied, truncated, nil
}

func contentEncodings(value string) []string {
	var result []string
	for _, item := range strings.Split(strings.ToLower(value), ",") {
		if encoding := strings.TrimSpace(item); encoding != "" {
			result = append(result, encoding)
		}
	}
	return result
}

func decodeGzip(body []byte, limit int) ([]byte, bool, error) {
	reader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, false, err
	}
	defer reader.Close()
	return readDecoded(reader, limit)
}

func decodeDeflate(body []byte, limit int) ([]byte, bool, error) {
	reader, err := zlib.NewReader(bytes.NewReader(body))
	if err == nil {
		defer reader.Close()
		return readDecoded(reader, limit)
	}
	raw := flate.NewReader(bytes.NewReader(body))
	defer raw.Close()
	return readDecoded(raw, limit)
}

func readDecoded(reader io.Reader, limit int) ([]byte, bool, error) {
	if limit < 1 {
		limit = 2_000_000
	}
	data, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	truncated := len(data) > limit
	if truncated {
		data = data[:limit]
	}
	// A bounded proxy capture may end before the compressed stream trailer.
	// The already-decoded prefix is still valid evidence and must be retained.
	if err != nil && !(len(data) > 0 && (errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF))) {
		return nil, false, err
	}
	return data, truncated || err != nil, nil
}
