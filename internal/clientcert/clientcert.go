package clientcert

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"jungle_happy_Scan/internal/model"
	"software.sslmate.com/src/go-pkcs12"
)

const MaxEncodedBytes = 3_000_000

// Parse validates and decodes a request-scoped client identity. It deliberately
// returns only a tls.Certificate so the original PFX bytes and password do not
// survive in task state or reports.
func Parse(input *model.ClientTLSInput) (*tls.Certificate, error) {
	if input == nil {
		return nil, nil
	}
	format := strings.ToLower(strings.TrimSpace(input.Format))
	if format == "" && input.File != "" {
		format = strings.TrimPrefix(strings.ToLower(filepath.Ext(input.File)), ".")
	}
	switch format {
	case "pem", "pfx", "p12", "pkcs12":
	default:
		return nil, errors.New("client_tls.format 必须是 pem、pfx 或 p12")
	}
	var data []byte
	if input.File != "" {
		if !filepath.IsAbs(input.File) {
			return nil, errors.New("client_tls_file 必须是服务器上的绝对路径")
		}
		info, err := os.Stat(input.File)
		if err != nil {
			return nil, errors.New("客户端 TLS 证书文件不存在或不可读")
		}
		if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 2_000_000 {
			return nil, errors.New("客户端 TLS 证书必须是 1 字节到 2 MiB 的普通文件")
		}
		data, err = os.ReadFile(input.File)
		if err != nil {
			return nil, errors.New("客户端 TLS 证书文件不存在或不可读")
		}
	} else {
		encoded := strings.TrimSpace(input.DataBase64)
		if encoded == "" {
			return nil, errors.New("client_tls.data_base64 或 client_tls_file 不能为空")
		}
		if len(encoded) > MaxEncodedBytes {
			return nil, errors.New("客户端 TLS 证书超过 2 MiB 限制")
		}
		var err error
		data, err = base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, errors.New("客户端 TLS 证书不是有效 Base64")
		}
	}
	defer clear(data)
	if len(data) == 0 || len(data) > 2_000_000 {
		return nil, errors.New("客户端 TLS 证书大小必须在 1 字节到 2 MiB 之间")
	}
	if format == "pem" {
		certificate, err := tls.X509KeyPair(data, data)
		if err != nil {
			return nil, fmt.Errorf("PEM 客户端证书必须同时包含证书链和未加密私钥: %w", err)
		}
		return &certificate, nil
	}
	privateKey, leaf, chain, err := pkcs12.DecodeChain(data, input.Password)
	if err != nil {
		return nil, errors.New("PFX/P12 解析失败，请检查文件和密码")
	}
	certificate := tls.Certificate{
		Certificate: make([][]byte, 0, 1+len(chain)),
		PrivateKey:  privateKey,
		Leaf:        leaf,
	}
	certificate.Certificate = append(certificate.Certificate, append([]byte(nil), leaf.Raw...))
	for _, item := range chain {
		certificate.Certificate = append(certificate.Certificate, append([]byte(nil), item.Raw...))
	}
	return &certificate, nil
}

// FromScanInput accepts the nested asynchronous contract and the convenient
// top-level fields used by jungle_happy_scan. Inline data takes precedence.
func FromScanInput(input model.ScanInput) (*tls.Certificate, error) {
	spec := input.ClientTLS
	if spec == nil && strings.TrimSpace(input.ClientTLSFile) != "" {
		spec = &model.ClientTLSInput{File: strings.TrimSpace(input.ClientTLSFile), Password: input.ClientTLSPassword}
	}
	return Parse(spec)
}
