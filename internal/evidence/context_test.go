package evidence

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSelectTextMarkerLineWindow(t *testing.T) {
	lines := make([]string, 100)
	for i := range lines {
		lines[i] = "line-" + string(rune('a'+i%26))
	}
	lines[50] = "line-50 TARGET"
	selection := SelectText(strings.Join(lines, "\n"), "target")
	got := strings.Split(selection.Text, "\n")
	if selection.Strategy != "marker_lines" || !selection.Clipped || selection.StartLine != 21 || selection.EndLine != 81 {
		t.Fatalf("unexpected marker selection metadata: %#v", selection)
	}
	if len(got) != 61 || got[0] != "line-u" || got[30] != "line-50 TARGET" || got[60] != "line-c" {
		t.Fatalf("unexpected marker window: first=%q marker=%q last=%q lines=%d", got[0], got[30], got[60], len(got))
	}
}

func TestSelectTextMarkerlessHeadTailAndCRLF(t *testing.T) {
	lines := make([]string, 100)
	for i := range lines {
		lines[i] = "line-" + string(rune('0'+i%10))
	}
	selection := SelectText(strings.Join(lines, "\r\n"), "not-present")
	if selection.Strategy != "head_tail_lines" || !selection.Clipped || selection.StartLine != 1 || selection.EndLine != 100 {
		t.Fatalf("unexpected markerless metadata: %#v", selection)
	}
	if !strings.Contains(selection.Text, omissionNotice) || !strings.HasPrefix(selection.Text, "line-0\n") || !strings.HasSuffix(selection.Text, "line-9") {
		t.Fatalf("markerless head/tail selection lost its boundaries: %q", selection.Text)
	}
	if strings.Contains(selection.Text, "\r") {
		t.Fatalf("CRLF was not normalized: %q", selection.Text)
	}
}

func TestSelectTextCompleteAndRepeatedMarkerUsesFirst(t *testing.T) {
	selection := SelectText("one\ntarget\nthree\ntarget", "TARGET")
	if selection.Strategy != "complete" || selection.Clipped || selection.MarkerLine != 2 || selection.SelectedLines != 4 {
		t.Fatalf("unexpected complete selection: %#v", selection)
	}
}

func TestSelectTextBoundsLongUTF8MarkerLine(t *testing.T) {
	text := strings.Repeat("前缀", 40_000) + "命中字段" + strings.Repeat("后缀", 40_000)
	selection := SelectText(text, "命中字段")
	if selection.Strategy != "marker_bytes" || !selection.Clipped || len(selection.Text) > MaxBodyBytes {
		t.Fatalf("unexpected UTF-8 byte selection: strategy=%s clipped=%v bytes=%d", selection.Strategy, selection.Clipped, len(selection.Text))
	}
	if !utf8.ValidString(selection.Text) || !strings.Contains(selection.Text, "命中字段") {
		t.Fatalf("marker byte window is not valid UTF-8 evidence: valid=%v contains=%v", utf8.ValidString(selection.Text), strings.Contains(selection.Text, "命中字段"))
	}
}

func TestSelectTextUsesBoundedHeadTailBytes(t *testing.T) {
	text := strings.Repeat("x", MaxBodyBytes+1024)
	selection := SelectText(text, "")
	if selection.Strategy != "head_tail_bytes" || len(selection.Text) > MaxBodyBytes || !strings.Contains(selection.Text, omissionNotice) {
		t.Fatalf("unexpected bounded head/tail selection: %#v", selection)
	}
}

func TestIsBinaryUsesMediaTypeAndContent(t *testing.T) {
	if !IsBinary("application/octet-stream", []byte("plain")) {
		t.Fatal("octet-stream must be treated as binary")
	}
	if !IsBinary("text/plain; charset=utf-8", []byte{0, 1, 2}) {
		t.Fatal("control-heavy text body must be treated as binary")
	}
	if IsBinary("application/json", []byte(`{"ok":true}`)) {
		t.Fatal("valid JSON must remain textual")
	}
}
