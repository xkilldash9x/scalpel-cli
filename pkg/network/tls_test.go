// internal/network/tls_test.go
package network

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// tlsTestHelper manages the lifecycle of dynamically generated certificates and test servers.
type tlsTestHelper struct {
	t *testing.T

	// CA Certificate (Root)
	caCert    *x509.Certificate
	caKey     *ecdsa.PrivateKey
	caPool    *x509.CertPool
	caCertPEM []byte
	caKeyPEM  []byte

	// Server Certificate (Leaf, signed by CA)
	serverCert tls.Certificate
	serverName string

	// Test Server
	listener   net.Listener
	serverAddr string
}

// newTLSTestHelper creates a new helper, generating the CA and a server certificate.
func newTLSTestHelper(t *testing.T) *tlsTestHelper {
	t.Helper()
	helper := &tlsTestHelper{t: t}
	helper.generateCA()
	helper.generateServerCert()
	return helper
}

// generateCA creates a self-signed Root CA certificate.
func (h *tlsTestHelper) generateCA() {
	// Use ECDSA P-256 for fast key generation in tests.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(h.t, err, "Failed to generate CA key")

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Scalpel Testing CA"},
			CommonName:   "Scalpel Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(h.t, err, "Failed to create CA certificate")

	cert, err := x509.ParseCertificate(derBytes)
	require.NoError(h.t, err, "Failed to parse generated CA certificate")

	h.caCert = cert
	h.caKey = priv
	h.caPool = x509.NewCertPool()
	h.caPool.AddCert(cert)

	// Generate PEM blocks for proxy configuration
	h.caCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	// Use PKCS8 for broader compatibility
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(h.t, err, "Failed to marshal CA key")
	h.caKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
}

// generateServerCert creates a leaf certificate signed by the generated CA.
func (h *tlsTestHelper) generateServerCert() {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(h.t, err, "Failed to generate server key")

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	h.serverName = "localhost"
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Scalpel Testing Server"},
			CommonName:   h.serverName,
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(1 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// Crucial: Include DNS and IP SANs for robust testing
		DNSNames:    []string{h.serverName},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	// Sign with the CA
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, h.caCert, &priv.PublicKey, h.caKey)
	require.NoError(h.t, err, "Failed to create server certificate")

	// Create tls.Certificate structure
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(h.t, err, "Failed to marshal server key")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(h.t, err, "Failed to load server X509 key pair")

	h.serverCert = tlsCert
}

// startTLSServer starts a simple TLS echo server using the generated server certificate.
func (h *tlsTestHelper) startTLSServer(config *tls.Config) {
	if config == nil {
		config = &tls.Config{
			Certificates: []tls.Certificate{h.serverCert},
		}
	}

	// Listen on ephemeral port
	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
	require.NoError(h.t, err, "Failed to start TLS listener")

	h.listener = listener
	h.serverAddr = listener.Addr().String()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				// Check if the listener was closed intentionally
				if errors.Is(err, net.ErrClosed) {
					return
				}
				h.t.Logf("TLS server accept error: %v", err)
				continue
			}
			// Echo handler
			go func(c net.Conn) {
				defer c.Close()
				// Ensure handshake is complete (important for inspecting connection state)
				if tlsConn, ok := c.(*tls.Conn); ok {
					if err := tlsConn.Handshake(); err != nil {
						return
					}
				}
				// Simple echo
				io.Copy(c, c)
			}(conn)
		}
	}()
}

// close stops the test server if running.
func (h *tlsTestHelper) close() {
	if h.listener != nil {
		h.listener.Close()
	}
}
