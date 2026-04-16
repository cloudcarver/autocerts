package renewal

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cloudcarver/autocerts/internal/certstore"
	"github.com/cloudcarver/autocerts/internal/certutil"
	"github.com/cloudcarver/autocerts/internal/config"
	"github.com/cloudcarver/autocerts/internal/target"
)

func TestReconcilerGroupsBindingsByFingerprint(t *testing.T) {
	t.Parallel()

	issuer := &fakeIssuer{
		bundle: &certutil.Bundle{
			Domains:        []string{"example.com", "*.example.com"},
			CertificatePEM: "cert",
			PrivateKeyPEM:  "key",
			ExpiresAt:      time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
			Fingerprint:    "new-fingerprint",
		},
	}
	store := &fakeStore{
		metadata: &certstore.Metadata{
			Region:          "cn-hangzhou",
			CertificateID:   42,
			CertIdentifier:  "42-cn-hangzhou",
			CertificateName: "autocerts-example",
			DNSProvider:     config.DNSProviderCloudflare,
			ExpiresAt:       time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
		},
	}
	bindingOne := &fakeBinding{
		name:        "alb listener",
		region:      "cn-hangzhou",
		domains:     []string{"example.com", "*.example.com"},
		expiresAt:   time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC),
		fingerprint: "old-fingerprint",
	}
	bindingTwo := &fakeBinding{
		name:        "oss cname",
		region:      "cn-hangzhou",
		domains:     []string{"example.com", "*.example.com"},
		expiresAt:   time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC),
		fingerprint: "old-fingerprint",
	}

	reconciler := &Reconciler{
		Sources: []target.Source{
			fakeSource{bindings: []target.Binding{bindingOne, bindingTwo}},
		},
		Issuer:    issuer,
		Store:     store,
		Threshold: 7 * 24 * time.Hour,
		Now: func() time.Time {
			return time.Date(2026, 4, 16, 0, 0, 0, 0, time.UTC)
		},
	}

	result, err := reconciler.Run(context.Background(), false, func(domains []string) string {
		return "autocerts-example"
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if issuer.calls != 1 {
		t.Fatalf("expected issuer to be called once, got %d", issuer.calls)
	}
	if store.uploadCalls != 1 {
		t.Fatalf("expected store to be called once, got %d", store.uploadCalls)
	}
	if issuer.provider != config.DNSProviderCloudflare {
		t.Fatalf("expected cloudflare provider, got %q", issuer.provider)
	}
	if store.uploadRequests[0].DNSProvider != config.DNSProviderCloudflare {
		t.Fatalf("expected upload request to preserve provider, got %q", store.uploadRequests[0].DNSProvider)
	}
	if bindingOne.replaceCalls != 1 || bindingTwo.replaceCalls != 1 {
		t.Fatalf("expected both bindings to be updated once, got %d and %d", bindingOne.replaceCalls, bindingTwo.replaceCalls)
	}
	if result.Renewed != 1 || result.Updated != 2 {
		t.Fatalf("unexpected reconcile result: %#v", result)
	}
}

func TestReconcilerDryRunDoesNotMutate(t *testing.T) {
	t.Parallel()

	issuer := &fakeIssuer{}
	store := &fakeStore{
		metadata: &certstore.Metadata{
			Region:          "cn-hangzhou",
			CertificateID:   100,
			CertIdentifier:  "100-cn-hangzhou",
			CertificateName: "autocerts-api",
			DNSProvider:     config.DNSProviderCloudflare,
		},
	}
	binding := &fakeBinding{
		name:        "fc custom domain",
		region:      "cn-hangzhou",
		domains:     []string{"api.example.com"},
		expiresAt:   time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC),
		fingerprint: "old-fingerprint",
	}

	reconciler := &Reconciler{
		Sources: []target.Source{
			fakeSource{bindings: []target.Binding{binding}},
		},
		Issuer:    issuer,
		Store:     store,
		Threshold: 7 * 24 * time.Hour,
		Now: func() time.Time {
			return time.Date(2026, 4, 16, 0, 0, 0, 0, time.UTC)
		},
	}

	result, err := reconciler.Run(context.Background(), true, func(domains []string) string {
		return "autocerts-api"
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if issuer.calls != 0 || store.uploadCalls != 0 || binding.replaceCalls != 0 {
		t.Fatalf("dry-run should not mutate state")
	}
	if !result.DryRun || len(result.Actions) != 1 {
		t.Fatalf("unexpected dry-run result: %#v", result)
	}
}

func TestReconcilerUsesBindingsFromPartiallyFailedSource(t *testing.T) {
	t.Parallel()

	issuer := &fakeIssuer{
		bundle: &certutil.Bundle{
			Domains:        []string{"example.com"},
			CertificatePEM: "cert",
			PrivateKeyPEM:  "key",
			ExpiresAt:      time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
			Fingerprint:    "new-fingerprint",
		},
	}
	store := &fakeStore{
		metadata: &certstore.Metadata{
			Region:          "cn-hangzhou",
			CertificateID:   7,
			CertIdentifier:  "7-cn-hangzhou",
			CertificateName: "autocerts-example",
			DNSProvider:     config.DNSProviderAliyun,
			ExpiresAt:       time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
		},
	}
	binding := &fakeBinding{
		name:        "partially failed source binding",
		region:      "cn-hangzhou",
		domains:     []string{"example.com"},
		expiresAt:   time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC),
		fingerprint: "old-fingerprint",
	}

	reconciler := &Reconciler{
		Sources: []target.Source{
			fakeSource{bindings: []target.Binding{binding}, err: errors.New("warn only")},
		},
		Issuer:    issuer,
		Store:     store,
		Threshold: 7 * 24 * time.Hour,
		Now: func() time.Time {
			return time.Date(2026, 4, 16, 0, 0, 0, 0, time.UTC)
		},
	}

	result, err := reconciler.Run(context.Background(), false, func(domains []string) string {
		return "autocerts-example"
	})
	if err == nil {
		t.Fatalf("expected aggregated partial discovery error")
	}
	if result.Updated != 1 {
		t.Fatalf("expected discovered binding to still be updated, got %#v", result)
	}
}

func TestReconcilerUploadsOnceForMultipleRegions(t *testing.T) {
	t.Parallel()

	issuer := &fakeIssuer{
		bundle: &certutil.Bundle{
			Domains:        []string{"example.com", "*.example.com"},
			CertificatePEM: "cert",
			PrivateKeyPEM:  "key",
			ExpiresAt:      time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
			Fingerprint:    "new-fingerprint",
		},
	}
	store := &fakeStore{
		metadata: &certstore.Metadata{
			CertificateID:   102,
			CertIdentifier:  "102-global",
			CertificateName: "autocerts-example",
			DNSProvider:     config.DNSProviderCloudflare,
			ExpiresAt:       time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
		},
	}
	bindingOne := &fakeBinding{
		name:        "alb listener",
		region:      "cn-hangzhou",
		domains:     []string{"example.com", "*.example.com"},
		expiresAt:   time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC),
		fingerprint: "old-fingerprint",
	}
	bindingTwo := &fakeBinding{
		name:        "fc custom domain",
		region:      "cn-beijing",
		domains:     []string{"example.com", "*.example.com"},
		expiresAt:   time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC),
		fingerprint: "old-fingerprint",
	}

	reconciler := &Reconciler{
		Sources: []target.Source{
			fakeSource{bindings: []target.Binding{bindingOne, bindingTwo}},
		},
		Issuer:    issuer,
		Store:     store,
		Threshold: 7 * 24 * time.Hour,
		Now: func() time.Time {
			return time.Date(2026, 4, 16, 0, 0, 0, 0, time.UTC)
		},
	}

	result, err := reconciler.Run(context.Background(), false, func(domains []string) string {
		return "autocerts-example"
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if issuer.calls != 1 {
		t.Fatalf("expected issuer to be called once, got %d", issuer.calls)
	}
	if store.uploadCalls != 1 {
		t.Fatalf("expected store to be called once, got %d", store.uploadCalls)
	}
	if bindingOne.replaceCalls != 1 || bindingTwo.replaceCalls != 1 {
		t.Fatalf("expected both bindings to be updated once, got %d and %d", bindingOne.replaceCalls, bindingTwo.replaceCalls)
	}
	if result.Renewed != 1 || result.Updated != 2 || len(result.Actions) != 1 || len(result.Actions[0].Uploads) != 1 {
		t.Fatalf("unexpected reconcile result: %#v", result)
	}
	if result.Actions[0].Uploads[0].CertIdentifier != "102-global" {
		t.Fatalf("unexpected upload metadata: %#v", result.Actions[0].Uploads)
	}
}

func TestReconcilerTreatsWarningOnlyDiscoveryAsNonFatal(t *testing.T) {
	t.Parallel()

	reconciler := &Reconciler{
		Sources: []target.Source{
			fakeSource{
				err: target.Warningf("resolve OSS certificate 1-cn-hangzhou for cn-hangzhou/demo: certificate %q not found in CAS", "1-cn-hangzhou"),
			},
		},
		Issuer:    &fakeIssuer{},
		Store:     &fakeStore{},
		Threshold: 7 * 24 * time.Hour,
		Now: func() time.Time {
			return time.Date(2026, 4, 16, 0, 0, 0, 0, time.UTC)
		},
	}

	result, err := reconciler.Run(context.Background(), false, func(domains []string) string {
		return "autocerts-example"
	})
	if err != nil {
		t.Fatalf("expected warning-only reconcile to succeed, got: %v", err)
	}
	if len(result.Warnings) != 1 {
		t.Fatalf("expected one warning, got %#v", result.Warnings)
	}
}

type fakeIssuer struct {
	calls    int
	provider config.DNSProviderType
	bundle   *certutil.Bundle
}

func (f *fakeIssuer) Issue(_ context.Context, _ []string, provider config.DNSProviderType) (*certutil.Bundle, error) {
	f.calls++
	f.provider = provider
	return f.bundle, nil
}

type fakeStore struct {
	uploadCalls      int
	uploadRequests   []certstore.UploadRequest
	findRegions      []string
	metadata         *certstore.Metadata
	metadataByRegion map[string]*certstore.Metadata
}

func (f *fakeStore) Upload(_ context.Context, request certstore.UploadRequest) (*certstore.Metadata, error) {
	f.uploadCalls++
	f.uploadRequests = append(f.uploadRequests, request)
	if f.metadataByRegion != nil {
		if metadata, ok := f.metadataByRegion[request.Region]; ok {
			return metadata, nil
		}
	}
	if f.metadata != nil {
		metadata := *f.metadata
		if metadata.CertIdentifier == "" {
			metadata.CertIdentifier = "generated"
		}
		return &metadata, nil
	}
	return nil, nil
}

func (f *fakeStore) FindByIdentifier(_ context.Context, region, _ string) (*certstore.Metadata, error) {
	f.findRegions = append(f.findRegions, region)
	if f.metadataByRegion != nil {
		return f.metadataByRegion[region], nil
	}
	return f.metadata, nil
}

func (f *fakeStore) FindByFingerprint(_ context.Context, region, _ string) (*certstore.Metadata, error) {
	f.findRegions = append(f.findRegions, region)
	if f.metadataByRegion != nil {
		return f.metadataByRegion[region], nil
	}
	return f.metadata, nil
}

func (f *fakeStore) FindLatestByDomains(_ context.Context, _ []string, _ config.DNSProviderType) (*certstore.Metadata, error) {
	return f.metadata, nil
}

func (f *fakeStore) SmokeTest(_ context.Context) error {
	return nil
}

type fakeBinding struct {
	name         string
	region       string
	domains      []string
	expiresAt    time.Time
	fingerprint  string
	replaceCalls int
}

func (f *fakeBinding) ResourceType() string {
	return "fake"
}

func (f *fakeBinding) DisplayName() string {
	return f.name
}

func (f *fakeBinding) Region() string {
	return f.region
}

func (f *fakeBinding) Domains() []string {
	return append([]string(nil), f.domains...)
}

func (f *fakeBinding) ExpiresAt() time.Time {
	return f.expiresAt
}

func (f *fakeBinding) Fingerprint() string {
	return f.fingerprint
}

func (f *fakeBinding) Replace(_ context.Context, _ target.Material) error {
	f.replaceCalls++
	return nil
}

type fakeSource struct {
	bindings []target.Binding
	err      error
}

func (f fakeSource) Name() string {
	return "fake"
}

func (f fakeSource) Discover(_ context.Context) ([]target.Binding, error) {
	return f.bindings, f.err
}

func (f fakeSource) SmokeTest(_ context.Context) error {
	return nil
}
