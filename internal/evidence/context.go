// Package evidence contains the bounded, finding-oriented message views that
// are shared by request and response evidence formatters.
package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"mime"
	"strings"
	"unicode/utf8"
)

const (
	// EvidenceContextLinesBefore and EvidenceContextLinesAfter define the
	// evidence-first line window. The matching line is included in addition to
	// both sides, so a complete line-oriented selection contains at most 61
	// source lines.
	EvidenceContextLinesBefore = 30
	EvidenceContextLinesAfter  = 30
	MaxBodyLines               = EvidenceContextLinesBefore + EvidenceContextLinesAfter + 1
	// MaxBodyBytes bounds the selected, display-safe body context. Headers are
	// deliberately outside this bound.
	MaxBodyBytes = 64 * 1024
)

const omissionNotice = "...[evidence context omitted]..."

// Selection describes a deterministic body context selection. Line numbers
// are one-based and are populated when a line-oriented selection was used.
type Selection struct {
	Text           string
	Strategy       string
	Clipped        bool
	TotalLines     int
	SelectedLines  int
	StartLine      int
	EndLine        int
	MarkerLine     int
	AvailableBytes int
	SelectedBytes  int
}

// SelectText returns a valid UTF-8, bounded body context. Marker matching is
// case-insensitive but otherwise preserves the original whitespace and line
// structure. The first marker occurrence is used when a marker occurs more
// than once.
func SelectText(text, marker string) Selection {
	text = normalizeText(text)
	lines := splitLines(text)
	result := Selection{TotalLines: len(lines), AvailableBytes: len(text)}
	if len(text) == 0 {
		result.Strategy = "complete"
		return result
	}

	marker = strings.TrimSpace(marker)
	markerPos := markerIndex(text, marker)
	markerLine := lineAt(text, markerPos)
	if markerPos >= 0 {
		result.MarkerLine = markerLine + 1
	}

	if len(lines) <= MaxBodyLines && len(text) <= MaxBodyBytes {
		result.Text = text
		result.Strategy = "complete"
		result.SelectedLines = len(lines)
		if len(lines) > 0 {
			result.StartLine, result.EndLine = 1, len(lines)
		}
		result.SelectedBytes = len(text)
		return result
	}

	if markerPos >= 0 && len(lines) > 0 {
		start := markerLine - EvidenceContextLinesBefore
		if start < 0 {
			start = 0
		}
		end := markerLine + EvidenceContextLinesAfter + 1
		if end > len(lines) {
			end = len(lines)
			start = end - MaxBodyLines
			if start < 0 {
				start = 0
			}
		}
		selected := strings.Join(lines[start:end], "\n")
		if len(selected) <= MaxBodyBytes {
			return lineSelection(selected, "marker_lines", true, len(text), len(lines), start+1, end, markerLine+1)
		}
		selected = markerWindow(text, markerPos, len(marker), MaxBodyBytes)
		return byteSelection(selected, "marker_bytes", true, len(text), len(lines), markerLine+1)
	}

	if len(lines) > MaxBodyLines {
		selected := joinHeadTail(lines)
		if len(selected) <= MaxBodyBytes {
			return lineSelection(selected, "head_tail_lines", true, len(text), len(lines), 1, len(lines), 0)
		}
	}
	selected := headTailWindow(text, MaxBodyBytes)
	return byteSelection(selected, "head_tail_bytes", true, len(text), len(lines), 0)
}

func normalizeText(text string) string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	return strings.ToValidUTF8(text, "\uFFFD")
}

func splitLines(text string) []string {
	if text == "" {
		return nil
	}
	lines := strings.Split(text, "\n")
	// A final line ending terminates the preceding line; it does not create a
	// second empty body line for evidence-counting purposes.
	if len(lines) > 1 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func markerIndex(text, marker string) int {
	if marker == "" {
		return -1
	}
	return strings.Index(strings.ToLower(text), strings.ToLower(marker))
}

func lineAt(text string, pos int) int {
	if pos < 0 {
		return -1
	}
	return strings.Count(text[:pos], "\n")
}

func lineSelection(text, strategy string, clipped bool, available, total, start, end, marker int) Selection {
	selectedLines := 0
	if end >= start {
		selectedLines = end - start + 1
	}
	if strategy == "head_tail_lines" {
		selectedLines = minInt(MaxBodyLines, total)
	}
	return Selection{
		Text: text, Strategy: strategy, Clipped: clipped,
		TotalLines: total, SelectedLines: selectedLines,
		StartLine: start, EndLine: end, MarkerLine: marker,
		AvailableBytes: available, SelectedBytes: len(text),
	}
}

func byteSelection(text, strategy string, clipped bool, available, total, marker int) Selection {
	return Selection{
		Text: text, Strategy: strategy, Clipped: clipped,
		TotalLines: total, MarkerLine: marker,
		SelectedBytes: len(text), AvailableBytes: available,
	}
}

func joinHeadTail(lines []string) string {
	if len(lines) <= MaxBodyLines {
		return strings.Join(lines, "\n")
	}
	head := lines[:15]
	tail := lines[len(lines)-15:]
	return strings.Join(head, "\n") + "\n" + omissionNotice + "\n" + strings.Join(tail, "\n")
}

func markerWindow(text string, markerPos, markerLen, limit int) string {
	if len(text) <= limit {
		return text
	}
	if markerLen > limit {
		markerLen = limit
	}
	available := limit - markerLen
	start := markerPos - available/2
	if start < 0 {
		start = 0
	}
	end := start + limit
	if end > len(text) {
		end = len(text)
		start = end - limit
		if start < 0 {
			start = 0
		}
	}
	return safeSlice(text, start, end)
}

func headTailWindow(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	reserve := len(omissionNotice) + 2
	available := limit - reserve
	if available < 2 {
		return safeSlice(text, 0, limit)
	}
	headBytes := available / 2
	tailBytes := available - headBytes
	head := safeSlice(text, 0, headBytes)
	tail := safeSlice(text, len(text)-tailBytes, len(text))
	return head + "\n" + omissionNotice + "\n" + tail
}

func safeSlice(text string, start, end int) string {
	if start < 0 {
		start = 0
	}
	if end > len(text) {
		end = len(text)
	}
	if start > end {
		start = end
	}
	for start < end && start > 0 && !utf8.RuneStart(text[start]) {
		start++
	}
	for end > start && end < len(text) && !utf8.RuneStart(text[end]) {
		end--
	}
	return text[start:end]
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

// IsBinary reports whether the body should be represented by metadata instead
// of being rendered as text. Explicit binary media types take precedence, and
// otherwise invalid UTF-8 or embedded NUL/control bytes are treated as binary.
func IsBinary(contentType string, body []byte) bool {
	mediaType := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	if parsed, _, err := mime.ParseMediaType(contentType); err == nil {
		mediaType = strings.ToLower(parsed)
	}
	if strings.HasPrefix(mediaType, "image/") || strings.HasPrefix(mediaType, "audio/") || strings.HasPrefix(mediaType, "video/") {
		return true
	}
	switch mediaType {
	case "application/octet-stream", "application/zip", "application/gzip", "application/x-gzip", "application/pdf", "application/wasm", "application/x-7z-compressed", "application/x-rar-compressed":
		return true
	}
	if !utf8.Valid(body) {
		return true
	}
	return bytes.IndexByte(body, 0) >= 0 || controlRatio(body) > 0.10
}

func controlRatio(body []byte) float64 {
	if len(body) == 0 {
		return 0
	}
	controls := 0
	for _, value := range body {
		if (value < 0x09) || (value > 0x0d && value < 0x20) {
			controls++
		}
	}
	return float64(controls) / float64(len(body))
}

func SHA256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
