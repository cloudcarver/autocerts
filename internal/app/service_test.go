package app

import (
	"context"
	"testing"
	"time"

	"github.com/cloudcarver/autocerts/internal/certstore"
	"github.com/cloudcarver/autocerts/internal/certutil"
	"github.com/cloudcarver/autocerts/internal/config"
)

func TestIssueReusesExistingCertificateForExactDomainsAndProvider(t *testing.T) {
	t.Parallel()

	store := &serviceStoreStub{
		latestByDomains: &certstore.Metadata{
			CertificateID:   42,
			CertIdentifier:  "42-global",
			CertificateName: "autocerts-example",
			DNSProvider:     config.DNSProviderCloudflare,
			Domains:         []string{"example.com", "*.example.com"},
			ExpiresAt:       time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		},
	}
	issuer := &serviceIssuerStub{
		bundle: &certutil.Bundle{
			Domains:        []string{"example.com", "*.example.com"},
			CertificatePEM: "cert",
			PrivateKeyPEM:  "key",
			ExpiresAt:      time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		},
	}
	service := &Service{
		Issuer: issuer,
		Store:  store,
		Prefix: "autocerts",
		Now: func() time.Time {
			return time.Date(2026, 4, 16, 0, 0, 0, 0, time.UTC)
		},
	}

	result, err := service.Issue(context.Background(), config.Request{
		Mode:        config.ModeIssue,
		Domains:     []string{"EXAMPLE.COM", "*.example.com"},
		DNSProvider: config.DNSProviderCloudflare,
	})
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}

	if !result.Reused {
		t.Fatalf("expected issue result to be reused")
	}
	if issuer.calls != 0 {
		t.Fatalf("expected issuer to not be called, got %d", issuer.calls)
	}
	if store.uploadCalls != 0 {
		t.Fatalf("expected upload to not be called, got %d", store.uploadCalls)
	}
	if result.CertificateName != "autocerts-example" {
		t.Fatalf("unexpected certificate name: %#v", result)
	}
	if len(result.Uploads) != 1 || result.Uploads[0].CertIdentifier != "42-global" {
		t.Fatalf("unexpected upload metadata: %#v", result.Uploads)
	}
}

func TestIssueCreatesNewCertificateWhenNoReusableMatchExists(t *testing.T) {
	t.Parallel()

	store := &serviceStoreStub{
		uploaded: &certstore.Metadata{
			CertificateID:   43,
			CertIdentifier:  "43-global",
			CertificateName: "autocerts-example",
			DNSProvider:     config.DNSProviderCloudflare,
			Domains:         []string{"example.com"},
			ExpiresAt:       time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		},
	}
	issuer := &serviceIssuerStub{
		bundle: &certutil.Bundle{
			Domains:        []string{"example.com"},
			CertificatePEM: "cert",
			PrivateKeyPEM:  "key",
			ExpiresAt:      time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		},
	}
	service := &Service{
		Issuer: issuer,
		Store:  store,
		Prefix: "autocerts",
		Now: func() time.Time {
			return time.Date(2026, 4, 16, 0, 0, 0, 0, time.UTC)
		},
	}

	result, err := service.Issue(context.Background(), config.Request{
		Mode:        config.ModeIssue,
		Domains:     []string{"example.com"},
		DNSProvider: config.DNSProviderCloudflare,
	})
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}

	if result.Reused {
		t.Fatalf("expected issue result to create a new certificate")
	}
	if issuer.calls != 1 {
		t.Fatalf("expected issuer to be called once, got %d", issuer.calls)
	}
	if store.uploadCalls != 1 {
		t.Fatalf("expected upload to be called once, got %d", store.uploadCalls)
	}
	if store.findLatestProvider != config.DNSProviderCloudflare {
		t.Fatalf("unexpected findLatest provider: %q", store.findLatestProvider)
	}
	if len(result.Uploads) != 1 || result.Uploads[0].CertIdentifier != "43-global" {
		t.Fatalf("unexpected upload metadata: %#v", result.Uploads)
	}
}

type serviceIssuerStub struct {
	calls  int
	bundle *certutil.Bundle
}

func (s *serviceIssuerStub) Issue(_ context.Context, _ []string, _ config.DNSProviderType) (*certutil.Bundle, error) {
	s.calls++
	return s.bundle, nil
}

func (s *serviceIssuerStub) SmokeTest(_ context.Context) error {
	return nil
}

type serviceStoreStub struct {
	findLatestDomains  []string
	findLatestProvider config.DNSProviderType
	latestByDomains    *certstore.Metadata
	uploadCalls        int
	uploaded           *certstore.Metadata
}

func (s *serviceStoreStub) Upload(_ context.Context, _ certstore.UploadRequest) (*certstore.Metadata, error) {
	s.uploadCalls++
	return s.uploaded, nil
}

func (s *serviceStoreStub) FindByIdentifier(_ context.Context, _, _ string) (*certstore.Metadata, error) {
	return nil, nil
}

func (s *serviceStoreStub) FindByFingerprint(_ context.Context, _, _ string) (*certstore.Metadata, error) {
	return nil, nil
}

func (s *serviceStoreStub) FindLatestByDomains(_ context.Context, domains []string, provider config.DNSProviderType) (*certstore.Metadata, error) {
	s.findLatestDomains = append([]string(nil), domains...)
	s.findLatestProvider = provider
	return s.latestByDomains, nil
}

func (s *serviceStoreStub) SmokeTest(_ context.Context) error {
	return nil
}
