package responsebody

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"testing"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

func TestDecodeGBKFromHeaderAndHTMLMeta(t *testing.T) {
	source := []byte(`<html><head><meta charset="GBK"></head><body>发送成功</body></html>`)
	encoded, _, err := transform.Bytes(simplifiedchinese.GBK.NewEncoder(), source)
	if err != nil {
		t.Fatal(err)
	}
	for _, contentType := range []string{"text/html; charset=gbk", "text/html"} {
		decoded, charset := Decode(encoded, contentType)
		if charset != "gbk" || !bytes.Contains(decoded, []byte("发送成功")) {
			t.Fatalf("charset=%q decoded=%q", charset, decoded)
		}
	}
}

func TestDecodeKeepsUTF8(t *testing.T) {
	body := []byte("中文 UTF-8")
	decoded, charset := Decode(body, "text/html")
	if charset != "utf-8" || !bytes.Equal(decoded, body) {
		t.Fatalf("charset=%q decoded=%q", charset, decoded)
	}
}

func TestDecodeDoesNotTreatBinaryAsGB18030(t *testing.T) {
	body := []byte{0xff, 0xd8, 0xff, 0x00, 0x81, 0x30, 0x81, 0x30}
	decoded, charset := Decode(body, "application/octet-stream")
	if charset != "binary" || !bytes.Equal(decoded, body) {
		t.Fatalf("binary response changed: charset=%q decoded=%x", charset, decoded)
	}
}

func TestDecodeContentEncodingGzipAndDeflate(t *testing.T) {
	source := []byte("HappyScan 中文响应")
	var gzipBody bytes.Buffer
	gzipWriter := gzip.NewWriter(&gzipBody)
	if _, err := gzipWriter.Write(source); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	var zlibBody bytes.Buffer
	zlibWriter := zlib.NewWriter(&zlibBody)
	if _, err := zlibWriter.Write(source); err != nil {
		t.Fatal(err)
	}
	if err := zlibWriter.Close(); err != nil {
		t.Fatal(err)
	}
	var rawDeflate bytes.Buffer
	rawWriter, _ := flate.NewWriter(&rawDeflate, flate.DefaultCompression)
	if _, err := rawWriter.Write(source); err != nil {
		t.Fatal(err)
	}
	if err := rawWriter.Close(); err != nil {
		t.Fatal(err)
	}
	for name, encoded := range map[string][]byte{"gzip": gzipBody.Bytes(), "deflate-zlib": zlibBody.Bytes(), "deflate-raw": rawDeflate.Bytes()} {
		encoding := "deflate"
		if name == "gzip" {
			encoding = "gzip"
		}
		decoded, applied, truncated, err := DecodeContentEncoding(encoded, encoding, 1024)
		if err != nil || !applied || truncated || !bytes.Equal(decoded, source) {
			t.Fatalf("%s decode failed: applied=%v truncated=%v decoded=%q err=%v", name, applied, truncated, decoded, err)
		}
	}
}

func TestDecodeContentEncodingIsBounded(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, _ = writer.Write(bytes.Repeat([]byte("A"), 4096))
	_ = writer.Close()
	decoded, applied, truncated, err := DecodeContentEncoding(compressed.Bytes(), "gzip", 128)
	if err != nil || !applied || !truncated || len(decoded) != 128 {
		t.Fatalf("bounded decode failed: applied=%v truncated=%v length=%d err=%v", applied, truncated, len(decoded), err)
	}
}
