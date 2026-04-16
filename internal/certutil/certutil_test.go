package certutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestBundleFromPEMParsesDomainsAndExpiry(t *testing.T) {
	t.Parallel()

	certificatePEM, privateKeyPEM, expectedExpiry := selfSignedCertificate(t)
	bundle, err := BundleFromPEM(nil, certificatePEM, privateKeyPEM)
	if err != nil {
		t.Fatalf("BundleFromPEM returned error: %v", err)
	}

	if len(bundle.Domains) != 2 {
		t.Fatalf("unexpected domains: %#v", bundle.Domains)
	}
	if bundle.ExpiresAt.IsZero() || !bundle.ExpiresAt.Equal(expectedExpiry.UTC()) {
		t.Fatalf("unexpected expiry: %v", bundle.ExpiresAt)
	}
	if bundle.Fingerprint == "" {
		t.Fatalf("expected fingerprint to be populated")
	}
}

func TestMakeCertificateNameFitsCASLimit(t *testing.T) {
	t.Parallel()

	name := MakeCertificateName("autocerts", []string{"*.very.long.example.com"}, time.Date(2026, 4, 16, 9, 30, 0, 0, time.UTC))
	if len(name) > 64 {
		t.Fatalf("certificate name exceeds CAS limit: %d", len(name))
	}
}

func selfSignedCertificate(t *testing.T) (string, string, time.Time) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}

	notAfter := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "*.example.com",
		},
		DNSNames:     []string{"*.example.com", "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SubjectKeyId: []byte{1, 2, 3, 4},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certificatePEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	privateKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}))
	return certificatePEM, privateKeyPEM, notAfter
}
