package plugin

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"strings"

	"jungle_happy_Scan/internal/httpraw"
	"jungle_happy_Scan/internal/model"
)

type Shiro struct{}

func (Shiro) Meta() model.PluginMeta {
	return StandardMeta("shiro", "Apache Shiro RememberMe", "识别 Shiro RememberMe，并用无 gadget、无命令的 Java null 对象流验证已知默认密钥。", "active", true)
}

func (p Shiro) Scan(ctx *Context) ([]model.Finding, error) {
	meta := p.Meta()
	// Do not require RememberMe to already be present. Shiro normally adds
	// deleteMe only after it receives an invalid RememberMe value, so passive
	// visibility alone misses the most common request shape.
	wasVisible := shiroRememberMeVisible(ctx.Request, ctx.Baseline)
	rule := ctx.Rule(meta.ID)
	total := 1 + len(rule.Payloads)
	ctx.Progress(meta.ID, 0, max(total, 1))
	invalid := withCookieValue(ctx.Request, "rememberMe", "jhs-invalid-rememberme")
	invalidResponse, err := ctx.Send(invalid)
	if err != nil {
		return nil, err
	}
	ctx.Progress(meta.ID, 1, total)
	invalidDeleted := shiroDeleteMe(invalidResponse)
	var findings []model.Finding
	if invalidDeleted && !shiroDeleteMe(ctx.Baseline) {
		findings = append(findings, Finding(meta, "识别到 Apache Shiro RememberMe", model.SeverityInfo, model.ConfidenceFirm, "cookie:rememberMe",
			"随机无效 RememberMe 值触发 deleteMe，响应行为符合 Apache Shiro。该结果只表示组件入口存在，不等同于反序列化利用。",
			"确认 Shiro 版本和 RememberMe 配置；若业务不需要则关闭 RememberMe。",
			[]model.Evidence{ctx.Evidence("无效 RememberMe 触发 deleteMe", invalid, &invalidResponse, map[string]any{"match": "rememberMe=deleteMe", "passively_visible": wasVisible})}))
	}
	for index, payload := range rule.Payloads {
		ciphertext, buildErr := shiroNullStream(payload.Payload)
		if buildErr != nil {
			ctx.Progress(meta.ID, index+2, total)
			continue
		}
		request := withCookieValue(ctx.Request, "rememberMe", ciphertext)
		response, sendErr := ctx.Send(request)
		if sendErr != nil {
			return findings, sendErr
		}
		ctx.Progress(meta.ID, index+2, total)
		if invalidDeleted && !shiroDeleteMe(response) {
			findings = append(findings, Finding(meta, "Apache Shiro RememberMe 使用已知密钥", model.SeverityCritical, model.ConfidenceCertain, "cookie:rememberMe",
				"随机密文被拒绝，而使用配置密钥加密的最小 Java null 对象流未触发 deleteMe。测试不包含 gadget、不实例化业务类、不执行命令。",
				"立即轮换为高强度随机密钥，升级 Shiro，清理历史 RememberMe Cookie；评估关闭该功能。",
				[]model.Evidence{
					ctx.Evidence("随机无效密文被拒绝", invalid, &invalidResponse, map[string]any{"match": "rememberMe=deleteMe"}),
					ctx.Evidence("安全 null 对象流通过密钥校验", request, &response, map[string]any{"paired_confirmed": true, "key_rule": payload.Name}),
				}, "CVE-2016-4437"))
			break
		}
	}
	return findings, nil
}

func shiroRememberMeVisible(request *httpraw.Request, baseline model.Response) bool {
	return strings.Contains(strings.ToLower(request.Header("Cookie")), "rememberme=") ||
		responseHeadersContain(baseline, "set-cookie", "rememberme=")
}

func shiroDeleteMe(response model.Response) bool {
	return responseHeadersContain(response, "set-cookie", "rememberme=deleteme")
}

func responseHeadersContain(response model.Response, name, expected string) bool {
	expected = strings.ToLower(expected)
	for _, value := range response.HeaderAll(name) {
		if strings.Contains(strings.ToLower(value), expected) {
			return true
		}
	}
	return false
}

func withCookieValue(request *httpraw.Request, name, value string) *httpraw.Request {
	cookie := request.Header("Cookie")
	parts := strings.Split(cookie, ";")
	found := false
	for index, part := range parts {
		key, _, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(key, name) {
			parts[index] = key + "=" + value
			found = true
		}
	}
	if !found {
		if strings.TrimSpace(cookie) == "" {
			parts = []string{name + "=" + value}
		} else {
			parts = append(parts, name+"="+value)
		}
	}
	return request.WithHeader("Cookie", strings.Join(parts, "; "))
}

func shiroNullStream(encodedKey string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encodedKey))
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	// STREAM_MAGIC, STREAM_VERSION, TC_NULL. It is deliberately not a gadget.
	plain := []byte{0xac, 0xed, 0x00, 0x05, 0x70}
	padding := aes.BlockSize - len(plain)%aes.BlockSize
	plain = append(plain, bytesRepeat(byte(padding), padding)...)
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	encrypted := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypted, plain)
	return base64.StdEncoding.EncodeToString(append(iv, encrypted...)), nil
}

func bytesRepeat(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}
