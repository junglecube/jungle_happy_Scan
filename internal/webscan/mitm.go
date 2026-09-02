package webscan

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const maxMITMCertificates = 256

type mitmCA struct {
	certificate *x509.Certificate
	privateKey  *ecdsa.PrivateKey
	certPEM     []byte
	mu          sync.Mutex
	leaves      map[string]tls.Certificate
	order       []string
}

func (m *Manager) ensureMITMCA() (*mitmCA, error) {
	m.mitmMu.Lock()
	defer m.mitmMu.Unlock()
	if m.mitm != nil {
		return m.mitm, nil
	}
	if m.mitmDir == "" {
		dir, err := os.MkdirTemp("", "jungle-happy-scan-proxy-ca-")
		if err != nil {
			return nil, err
		}
		m.mitmDir, m.ephemeralCA = dir, true
	}
	ca, err := loadOrCreateMITMCA(m.mitmDir)
	if err != nil {
		return nil, err
	}
	m.mitm = ca
	return ca, nil
}

func (m *Manager) RootCertificate() ([]byte, error) {
	ca, err := m.ensureMITMCA()
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), ca.certPEM...), nil
}

func loadOrCreateMITMCA(dir string) (*mitmCA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	certPath := filepath.Join(dir, "happy-scan-proxy-ca.pem")
	keyPath := filepath.Join(dir, "happy-scan-proxy-ca-key.pem")
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		certBlock, _ := pem.Decode(certPEM)
		keyBlock, _ := pem.Decode(keyPEM)
		if certBlock == nil || keyBlock == nil {
			return nil, errors.New("代理 CA 文件格式无效")
		}
		certificate, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return nil, err
		}
		privateKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, err
		}
		_ = os.Chmod(certPath, 0o600)
		_ = os.Chmod(keyPath, 0o600)
		return &mitmCA{certificate: certificate, privateKey: privateKey, certPEM: certPEM, leaves: make(map[string]tls.Certificate)}, nil
	}
	if !errors.Is(certErr, os.ErrNotExist) || !errors.Is(keyErr, os.ErrNotExist) {
		return nil, errors.New("代理 CA 证书或私钥不完整")
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "jungle_happy_Scan Proxy CA",
			Organization: []string{"jungle_happy_Scan"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := writePrivateFile(certPath, certPEM); err != nil {
		return nil, err
	}
	if err := writePrivateFile(keyPath, keyPEM); err != nil {
		return nil, err
	}
	return &mitmCA{certificate: certificate, privateKey: privateKey, certPEM: certPEM, leaves: make(map[string]tls.Certificate)}, nil
}

func writePrivateFile(path string, data []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".proxy-ca-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	ok := false
	defer func() {
		_ = temp.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temp.Write(data); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	return nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

func (ca *mitmCA) certificateFor(host string) (tls.Certificate, error) {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if certificate, ok := ca.leaves[host]; ok {
		return certificate, nil
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host, Organization: []string{"jungle_happy_Scan"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(0, 0, 14),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &privateKey.PublicKey, ca.privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	certificate := tls.Certificate{
		Certificate: [][]byte{der, ca.certificate.Raw},
		PrivateKey:  privateKey,
	}
	ca.leaves[host] = certificate
	ca.order = append(ca.order, host)
	if len(ca.order) > maxMITMCertificates {
		delete(ca.leaves, ca.order[0])
		ca.order = ca.order[1:]
	}
	return certificate, nil
}

func (m *Manager) connectMITM(session *Session, w http.ResponseWriter, r *http.Request) {
	ca, err := m.ensureMITMCA()
	if err != nil {
		http.Error(w, "HappyScan HTTPS 解密 CA 不可用", http.StatusBadGateway)
		return
	}
	host := hostname(r.Host)
	certificate, err := ca.certificateFor(host)
	if err != nil {
		http.Error(w, "HappyScan 无法签发目标证书", http.StatusBadGateway)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "HappyScan CONNECT is unavailable", http.StatusInternalServerError)
		return
	}
	client, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	session.mu.Lock()
	if len(session.tunnelConns) >= 256 {
		session.mu.Unlock()
		_ = client.Close()
		return
	}
	session.tunnels++
	session.counters.HTTPSTunnels++
	session.revision++
	session.tunnelConns[client] = client
	session.mu.Unlock()
	m.markSessionDirty(session.id)
	m.notifyChange()
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\nProxy-Agent: HappyScan-V3.5\r\n\r\n")); err != nil {
		_ = client.Close()
		return
	}
	tlsClient := tls.Server(client, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"http/1.1"},
	})
	go func() {
		defer func() {
			_ = tlsClient.Close()
			session.mu.Lock()
			delete(session.tunnelConns, client)
			session.mu.Unlock()
		}()
		if err := tlsClient.Handshake(); err != nil {
			return
		}
		handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			request.URL.Scheme = "https"
			if request.URL.Host == "" {
				request.URL.Host = request.Host
			}
			m.proxy(session, response, request)
		})
		_ = http.Serve(newSingleConnListener(tlsClient), handler)
	}()
}

type singleConnListener struct {
	conn net.Conn
	once sync.Once
	done chan struct{}
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	return &singleConnListener{conn: conn, done: make(chan struct{})}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var conn net.Conn
	l.once.Do(func() { conn = singleListenerConn{Conn: l.conn, closeListener: l.Close} })
	if conn == nil {
		<-l.done
		return nil, net.ErrClosed
	}
	return conn, nil
}

func (l *singleConnListener) Close() error {
	l.once.Do(func() {})
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return nil
}
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

type singleListenerConn struct {
	net.Conn
	closeListener func() error
}

func (c singleListenerConn) Close() error {
	err := c.Conn.Close()
	_ = c.closeListener()
	return err
}

func (s *Session) roundTripper(fallback *http.Transport) *http.Transport {
	if s.transport != nil {
		return s.transport
	}
	return fallback
}

func requestScheme(request *http.Request) string {
	scheme := strings.ToLower(request.URL.Scheme)
	if scheme == "" {
		scheme = "http"
	}
	return scheme
}
