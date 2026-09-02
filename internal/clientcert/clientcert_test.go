package clientcert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"jungle_happy_Scan/internal/model"
	"software.sslmate.com/src/go-pkcs12"
)

func testIdentity(t *testing.T) (*rsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(731),
		Subject:      pkix.Name{CommonName: "jungle-happy-scan-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return key, certificate, raw
}

func TestParseCombinedPEM(t *testing.T) {
	key, _, raw := testIdentity(t)
	pemData := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})...)
	certificate, err := Parse(&model.ClientTLSInput{Format: "pem", DataBase64: base64.StdEncoding.EncodeToString(pemData)})
	if err != nil || certificate == nil || len(certificate.Certificate) != 1 {
		t.Fatalf("combined PEM parse failed: cert=%#v err=%v", certificate, err)
	}
}

func TestParsePFXFromAbsolutePath(t *testing.T) {
	key, certificate, _ := testIdentity(t)
	pfx, err := pkcs12.Modern.Encode(key, certificate, nil, "jungle731")
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "client.pfx")
	if err := os.WriteFile(target, pfx, 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, err := FromScanInput(model.ScanInput{ClientTLSFile: target, ClientTLSPassword: "jungle731"})
	if err != nil || parsed == nil || parsed.Leaf == nil || parsed.Leaf.Subject.CommonName != "jungle-happy-scan-client" {
		t.Fatalf("PFX path parse failed: cert=%#v err=%v", parsed, err)
	}
}

func TestRejectRelativeClientTLSPath(t *testing.T) {
	if _, err := FromScanInput(model.ScanInput{ClientTLSFile: "client.pfx"}); err == nil {
		t.Fatal("relative client TLS path must be rejected")
	}
}
