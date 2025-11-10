package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

// CA encapsulates the components of a dynamically generated Certificate Authority,
// including its root certificate, private key, and a certificate pool containing
// the root. This is primarily used for TLS interception (MITM) in a proxy,
// where the CA is used to sign certificates for hosts on the fly.
type CA struct {
	// Cert is the parsed x509 root certificate of the Certificate Authority.
	Cert *x509.Certificate
	// PrivateKey is the RSA private key corresponding to the root certificate.
	PrivateKey *rsa.PrivateKey
	// CertPool is a pool containing only the CA's root certificate, which can
	// be used by a client to validate certificates signed by this CA.
	CertPool *x509.CertPool
}

// NewCA generates a new, self-signed Certificate Authority. It creates a 2048-bit
// RSA private key and a corresponding root certificate configured with the
// necessary properties to act as a CA. This CA can then be used to sign
// certificates for other domains, which is a key requirement for TLS interception.
//
// Returns an initialized CA struct or an error if key or certificate generation fails.
func NewCA() (*CA, error) {
	// First, generate a new private key. 2048 bits is a standard, secure choice.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Now, create a template for the self-signed certificate.
	template := x509.Certificate{
		SerialNumber: big.NewInt(1), // A unique serial number for the cert.
		Subject: pkix.Name{
			Organization: []string{"Scalpel-CLI Test CA"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365), // Valid for one year.

		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true, // This is critical, it marks the cert as a CA.
	}

	// Create the certificate using the template. We pass the template twice:
	// once as the certificate to create, and once as the parent/issuer,
	// because it is self-signed.
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	// Parse the generated certificate so we can use it.
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, err
	}

	// Create a certificate pool and add our new CA certificate to it.
	// This pool is used by clients to verify certificates signed by our CA.
	certPool := x509.NewCertPool()
	certPool.AddCert(cert)

	return &CA{
		Cert:       cert,
		PrivateKey: privateKey,
		CertPool:   certPool,
	}, nil
}

