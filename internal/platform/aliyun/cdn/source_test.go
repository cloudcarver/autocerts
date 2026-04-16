package cdn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	cdnsdk "github.com/alibabacloud-go/cdn-20180510/client"
	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudcarver/autocerts/internal/certutil"
	"github.com/cloudcarver/autocerts/internal/target"
)

func TestDiscoverReturnsHTTPSBinding(t *testing.T) {
	t.Parallel()

	certificatePEM, _, notAfter, fingerprint := selfSignedCertificate(t, []string{"cdn.example.com"})
	client := &clientStub{
		listHTTPSFunc: func(*cdnsdk.DescribeCdnHttpsDomainListRequest) (*cdnsdk.DescribeCdnHttpsDomainListResponse, error) {
			return &cdnsdk.DescribeCdnHttpsDomainListResponse{
				Body: &cdnsdk.DescribeCdnHttpsDomainListResponseBody{
					TotalCount: tea.Int32(1),
					CertInfos: &cdnsdk.DescribeCdnHttpsDomainListResponseBodyCertInfos{
						CertInfo: []*cdnsdk.DescribeCdnHttpsDomainListResponseBodyCertInfosCertInfo{
							new(cdnsdk.DescribeCdnHttpsDomainListResponseBodyCertInfosCertInfo).
								SetDomainName("cdn.example.com").
								SetCertExpireTime(notAfter.Format(time.RFC3339)),
						},
					},
				},
			}, nil
		},
		describeDetailFunc: func(*cdnsdk.DescribeDomainCertificateInfoRequest) (*cdnsdk.DescribeDomainCertificateInfoResponse, error) {
			return &cdnsdk.DescribeDomainCertificateInfoResponse{
				Body: &cdnsdk.DescribeDomainCertificateInfoResponseBody{
					CertInfos: &cdnsdk.DescribeDomainCertificateInfoResponseBodyCertInfos{
						CertInfo: []*cdnsdk.DescribeDomainCertificateInfoResponseBodyCertInfosCertInfo{
							new(cdnsdk.DescribeDomainCertificateInfoResponseBodyCertInfosCertInfo).
								SetDomainName("cdn.example.com").
								SetStatus("success").
								SetServerCertificateStatus("on").
								SetServerCertificate(certificatePEM).
								SetCertExpireTime(notAfter.Format(time.RFC3339)),
						},
					},
				},
			}, nil
		},
	}

	bindings, err := NewSourceWithClient(client).Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover returned error: %v", err)
	}
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d", len(bindings))
	}
	if got := bindings[0].DisplayName(); got != "cdn cdn.example.com" {
		t.Fatalf("unexpected display name: %q", got)
	}
	if got := bindings[0].Fingerprint(); got != fingerprint {
		t.Fatalf("unexpected fingerprint: %q", got)
	}
	if got := bindings[0].ExpiresAt(); !got.Equal(notAfter.UTC()) {
		t.Fatalf("unexpected expiry: %v", got)
	}
}

func TestDiscoverWarnsWhenCurrentCertificatePEMIsMissing(t *testing.T) {
	t.Parallel()

	client := &clientStub{
		listHTTPSFunc: func(*cdnsdk.DescribeCdnHttpsDomainListRequest) (*cdnsdk.DescribeCdnHttpsDomainListResponse, error) {
			return &cdnsdk.DescribeCdnHttpsDomainListResponse{
				Body: &cdnsdk.DescribeCdnHttpsDomainListResponseBody{
					TotalCount: tea.Int32(1),
					CertInfos: &cdnsdk.DescribeCdnHttpsDomainListResponseBodyCertInfos{
						CertInfo: []*cdnsdk.DescribeCdnHttpsDomainListResponseBodyCertInfosCertInfo{
							new(cdnsdk.DescribeCdnHttpsDomainListResponseBodyCertInfosCertInfo).SetDomainName("cdn.example.com"),
						},
					},
				},
			}, nil
		},
		describeDetailFunc: func(*cdnsdk.DescribeDomainCertificateInfoRequest) (*cdnsdk.DescribeDomainCertificateInfoResponse, error) {
			return &cdnsdk.DescribeDomainCertificateInfoResponse{
				Body: &cdnsdk.DescribeDomainCertificateInfoResponseBody{
					CertInfos: &cdnsdk.DescribeDomainCertificateInfoResponseBodyCertInfos{
						CertInfo: []*cdnsdk.DescribeDomainCertificateInfoResponseBodyCertInfosCertInfo{
							new(cdnsdk.DescribeDomainCertificateInfoResponseBodyCertInfosCertInfo).
								SetDomainName("cdn.example.com").
								SetServerCertificateStatus("on"),
						},
					},
				},
			}, nil
		},
	}

	bindings, err := NewSourceWithClient(client).Discover(context.Background())
	if len(bindings) != 0 {
		t.Fatalf("expected no bindings, got %d", len(bindings))
	}

	warnings, hardErr := target.SplitWarnings(err)
	if hardErr != nil {
		t.Fatalf("expected warning-only error, got %v", hardErr)
	}
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(warnings))
	}
}

func TestBindingReplaceUploadsPEMAndWaitsForNewFingerprint(t *testing.T) {
	t.Parallel()

	oldPEM, _, notAfter, oldFingerprint := selfSignedCertificate(t, []string{"cdn.example.com"})
	newPEM, newKey, _, newFingerprint := selfSignedCertificate(t, []string{"cdn.example.com"})

	client := &clientStub{}
	client.describeDetailFunc = func(*cdnsdk.DescribeDomainCertificateInfoRequest) (*cdnsdk.DescribeDomainCertificateInfoResponse, error) {
		certPEM := oldPEM
		if client.setRequests > 0 {
			certPEM = newPEM
		}
		return &cdnsdk.DescribeDomainCertificateInfoResponse{
			Body: &cdnsdk.DescribeDomainCertificateInfoResponseBody{
				CertInfos: &cdnsdk.DescribeDomainCertificateInfoResponseBodyCertInfos{
					CertInfo: []*cdnsdk.DescribeDomainCertificateInfoResponseBodyCertInfosCertInfo{
						new(cdnsdk.DescribeDomainCertificateInfoResponseBodyCertInfosCertInfo).
							SetDomainName("cdn.example.com").
							SetStatus("success").
							SetServerCertificateStatus("on").
							SetServerCertificate(certPEM),
					},
				},
			},
		}, nil
	}
	client.setFunc = func(request *cdnsdk.SetDomainServerCertificateRequest) (*cdnsdk.SetDomainServerCertificateResponse, error) {
		client.lastSetRequest = request
		client.setRequests++
		return &cdnsdk.SetDomainServerCertificateResponse{
			Body: &cdnsdk.SetDomainServerCertificateResponseBody{RequestId: tea.String("test")},
		}, nil
	}

	binding := &binding{
		client:      client,
		domainName:  "cdn.example.com",
		domains:     []string{"cdn.example.com"},
		expiresAt:   notAfter.UTC(),
		fingerprint: oldFingerprint,
	}

	err := binding.Replace(context.Background(), target.Material{
		Bundle: &certutil.Bundle{
			Domains:        []string{"cdn.example.com"},
			CertificatePEM: newPEM,
			PrivateKeyPEM:  newKey,
			Fingerprint:    newFingerprint,
		},
		CertificateName: "autocerts-cdn-example",
	})
	if err != nil {
		t.Fatalf("Replace returned error: %v", err)
	}
	if client.setRequests != 1 {
		t.Fatalf("expected one set request, got %d", client.setRequests)
	}
	if got := tea.StringValue(client.lastSetRequest.CertType); got != "upload" {
		t.Fatalf("unexpected cert type: %q", got)
	}
	if got := tea.StringValue(client.lastSetRequest.ServerCertificateStatus); got != "on" {
		t.Fatalf("unexpected SSL status: %q", got)
	}
	if got := tea.StringValue(client.lastSetRequest.ServerCertificate); got != newPEM {
		t.Fatalf("unexpected certificate payload")
	}
	if got := tea.StringValue(client.lastSetRequest.PrivateKey); got != newKey {
		t.Fatalf("unexpected private key payload")
	}
}

type clientStub struct {
	listHTTPSFunc      func(*cdnsdk.DescribeCdnHttpsDomainListRequest) (*cdnsdk.DescribeCdnHttpsDomainListResponse, error)
	describeDetailFunc func(*cdnsdk.DescribeDomainCertificateInfoRequest) (*cdnsdk.DescribeDomainCertificateInfoResponse, error)
	setFunc            func(*cdnsdk.SetDomainServerCertificateRequest) (*cdnsdk.SetDomainServerCertificateResponse, error)
	lastSetRequest     *cdnsdk.SetDomainServerCertificateRequest
	setRequests        int
}

func (c *clientStub) DescribeCdnHttpsDomainList(request *cdnsdk.DescribeCdnHttpsDomainListRequest) (*cdnsdk.DescribeCdnHttpsDomainListResponse, error) {
	return c.listHTTPSFunc(request)
}

func (c *clientStub) DescribeDomainCertificateInfo(request *cdnsdk.DescribeDomainCertificateInfoRequest) (*cdnsdk.DescribeDomainCertificateInfoResponse, error) {
	return c.describeDetailFunc(request)
}

func (c *clientStub) SetDomainServerCertificate(request *cdnsdk.SetDomainServerCertificateRequest) (*cdnsdk.SetDomainServerCertificateResponse, error) {
	return c.setFunc(request)
}

func selfSignedCertificate(t *testing.T, domains []string) (string, string, time.Time, string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}

	notAfter := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: domains[0],
		},
		DNSNames:     domains,
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
	bundle, err := certutil.BundleFromPEM(nil, certificatePEM, privateKeyPEM)
	if err != nil {
		t.Fatalf("BundleFromPEM returned error: %v", err)
	}
	return certificatePEM, privateKeyPEM, notAfter, bundle.Fingerprint
}
