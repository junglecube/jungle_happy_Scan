package signing

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

const (
	DefaultTimeout = 5 * time.Second
	maxSignedBytes = 5_000_000
	maxOutputBytes = 8_000_000
)

// Signer recalculates application-level signatures after a request mutation.
type Signer interface {
	Sign(context.Context, *httpraw.Request) (*httpraw.Request, error)
}

type adapter struct {
	input   model.SignatureInput
	client  *http.Client
	timeout time.Duration
}

type signatureEnvelope struct {
	Request string `json:"request"`
}

// New validates and constructs a request-scoped signer. A nil input disables
// signing, preserving the behavior of all existing callers.
func New(input *model.SignatureInput) (Signer, error) {
	if input == nil || strings.TrimSpace(input.Mode) == "" {
		return nil, nil
	}
	item := *input
	item.Mode = strings.ToLower(strings.TrimSpace(item.Mode))
	if item.TimeoutMS <= 0 {
		item.TimeoutMS = int(DefaultTimeout / time.Millisecond)
	}
	if item.TimeoutMS > 60_000 {
		return nil, errors.New("签名超时时间不能超过 60000 毫秒")
	}
	switch item.Mode {
	case "http":
		parsed, err := url.Parse(strings.TrimSpace(item.Endpoint))
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return nil, errors.New("HTTP 签名接口必须是合法的 http 或 https URL")
		}
		item.Endpoint = parsed.String()
	case "local_js":
		if strings.TrimSpace(item.Script) == "" {
			return nil, errors.New("本地 JS 签名模式必须提供 script")
		}
		item.Script = strings.TrimSpace(item.Script)
		item.Runtime = strings.TrimSpace(item.Runtime)
		if item.Runtime == "" {
			item.Runtime = "node"
		}
	default:
		return nil, errors.New("签名 mode 必须是 http 或 local_js")
	}
	return &adapter{
		input:   item,
		client:  &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		timeout: time.Duration(item.TimeoutMS) * time.Millisecond,
	}, nil
}

func (a *adapter) Sign(ctx context.Context, request *httpraw.Request) (*httpraw.Request, error) {
	if request == nil {
		return nil, errors.New("签名请求不能为空")
	}
	raw := request.RawExact()
	if len(raw) > maxSignedBytes {
		return nil, fmt.Errorf("待签名 HTTP 报文超过 %d 字节限制", maxSignedBytes)
	}
	encoded := base64.StdEncoding.EncodeToString(raw)
	signCtx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	var output []byte
	var err error
	switch a.input.Mode {
	case "http":
		output, err = a.signHTTP(signCtx, encoded)
	case "local_js":
		output, err = a.signLocal(signCtx, encoded)
	}
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(output)))
	if err != nil || len(decoded) == 0 {
		return nil, errors.New("签名器返回的内容不是合法的 Base64 HTTP 报文")
	}
	if len(decoded) > maxSignedBytes {
		return nil, fmt.Errorf("签名器返回的 HTTP 报文超过 %d 字节限制", maxSignedBytes)
	}
	signed, err := httpraw.Parse(string(decoded), request.Scheme)
	if err != nil {
		return nil, fmt.Errorf("签名器返回的 HTTP 报文无效: %w", err)
	}
	if signed.Method != request.Method || signed.Target != request.Target ||
		!strings.EqualFold(signed.Authority(), request.Authority()) {
		return nil, errors.New("签名器不能修改 HTTP 方法、目标或 Host")
	}
	signed.Scheme = request.Scheme
	return signed, nil
}

func (a *adapter) signHTTP(ctx context.Context, encoded string) ([]byte, error) {
	payload, err := json.Marshal(signatureEnvelope{Request: encoded})
	if err != nil {
		return nil, fmt.Errorf("编码签名接口请求失败: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.input.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("创建签名接口请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	response, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("调用签名接口失败: %w", err)
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxOutputBytes+1))
	if readErr != nil {
		return nil, fmt.Errorf("读取签名接口响应失败: %w", readErr)
	}
	if len(body) > maxOutputBytes {
		return nil, fmt.Errorf("签名接口响应超过 %d 字节限制", maxOutputBytes)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("签名接口返回 HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	var result signatureEnvelope
	if err := json.Unmarshal(bytes.TrimSpace(body), &result); err != nil {
		return nil, fmt.Errorf("签名接口响应不是合法 JSON: %w", err)
	}
	if strings.TrimSpace(result.Request) == "" {
		return nil, errors.New("签名接口响应缺少 request 字段")
	}
	return []byte(result.Request), nil
}

func (a *adapter) signLocal(ctx context.Context, encoded string) ([]byte, error) {
	command := exec.CommandContext(ctx, a.input.Runtime, a.input.Script, "-request", encoded)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return nil, fmt.Errorf("执行本地 JS 签名脚本失败: %s", message)
	}
	if len(output) > maxOutputBytes {
		return nil, fmt.Errorf("本地 JS 签名脚本输出超过 %d 字节限制", maxOutputBytes)
	}
	return output, nil
}
