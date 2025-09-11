package certs

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCA(t *testing.T) {
	// This test ensures that the NewCA function correctly generates all components.
	ca, err := NewCA()
	require.NoError(t, err, "NewCA should not return an error")

	// -- Basic sanity checks --
	assert.NotNil(t, ca, "The returned CA struct should not be nil")
	assert.NotNil(t, ca.Cert, "The CA certificate should not be nil")
	assert.NotNil(t, ca.PrivateKey, "The CA private key should not be nil")
	assert.NotNil(t, ca.CertPool, "The CA certificate pool should not be nil")

	// -- Validate the certificate's properties --
	assert.True(t, ca.Cert.IsCA, "The generated certificate must be a Certificate Authority")
	assert.Contains(t, ca.Cert.Subject.Organization, "Scalpel-CLI Test CA", "The organization should be set correctly")

	// -- Verify the certificate and key are a valid pair --
	err = ca.Cert.CheckSignature(ca.Cert.SignatureAlgorithm, ca.Cert.RawTBSCertificate, ca.Cert.Signature)
	assert.NoError(t, err, "The certificate's signature should be valid, verifying it's self-signed correctly")

	// -- Verify the cert pool --
	// We'll create a dummy certificate signed by our CA and see if the pool can verify it.
	// First, create a template for a server certificate.
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "test.scalpel.cli",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost", "test.scalpel.cli"},
	}

	// Generate a private key for the server cert.
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Sign the server certificate using our CA.
	derBytes, err := x509.CreateCertificate(rand.Reader, serverTemplate, ca.Cert, &serverKey.PublicKey, ca.PrivateKey)
	require.NoError(t, err)

	serverCert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err)

	// Now, try to verify the server certificate using the CA's pool.
	opts := x509.VerifyOptions{
		Roots:         ca.CertPool,
		Intermediates: x509.NewCertPool(), // No intermediates in this case.
		DNSName:       "test.scalpel.cli",
	}

	chains, err := serverCert.Verify(opts)
	assert.NoError(t, err, "Verification of a certificate signed by the CA should succeed")
	assert.Len(t, chains, 1, "Should find exactly one valid certificate chain")
}

