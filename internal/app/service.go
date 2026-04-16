package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cloudcarver/autocerts/internal/acme"
	"github.com/cloudcarver/autocerts/internal/certstore"
	"github.com/cloudcarver/autocerts/internal/certutil"
	"github.com/cloudcarver/autocerts/internal/config"
	"github.com/cloudcarver/autocerts/internal/renewal"
	"github.com/cloudcarver/autocerts/internal/target"
)

type Service struct {
	Issuer  acme.Issuer
	Store   certstore.Store
	Sources []target.Source

	Threshold time.Duration
	Prefix    string
	Now       func() time.Time
}

type Response struct {
	Mode       config.Mode     `json:"mode"`
	Issue      *IssueResult    `json:"issue,omitempty"`
	Reconcile  *renewal.Result `json:"reconcile,omitempty"`
	Smoke      *SmokeResult    `json:"smoke,omitempty"`
	OccurredAt time.Time       `json:"occurredAt"`
}

type IssueResult struct {
	DryRun          bool                   `json:"dryRun"`
	Reused          bool                   `json:"reused,omitempty"`
	CertificateName string                 `json:"certificateName"`
	DNSProvider     config.DNSProviderType `json:"dnsProvider,omitempty"`
	Domains         []string               `json:"domains"`
	Regions         []string               `json:"regions,omitempty"`
	Uploads         []IssueUpload          `json:"uploads,omitempty"`
	ExpiresAt       time.Time              `json:"expiresAt,omitempty"`
}

type IssueUpload struct {
	Region          string    `json:"region,omitempty"`
	CertificateID   int64     `json:"certificateId,omitempty"`
	CertIdentifier  string    `json:"certIdentifier,omitempty"`
	CertificateName string    `json:"certificateName,omitempty"`
	ExpiresAt       time.Time `json:"expiresAt,omitempty"`
}

type SmokeResult struct {
	Checks []SmokeCheck `json:"checks"`
}

type SmokeCheck struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

func (s *Service) Issue(ctx context.Context, request config.Request) (*IssueResult, error) {
	now := s.now()
	domains := certutil.NormalizeDomains(request.Domains)
	name := request.CertificateName
	if name == "" {
		name = certutil.MakeCertificateName(s.Prefix, domains, now)
	}

	result := &IssueResult{
		DryRun:          request.DryRun,
		CertificateName: name,
		DNSProvider:     request.DNSProvider,
		Domains:         domains,
		Regions:         append([]string(nil), request.Regions...),
	}
	if request.DryRun {
		return result, nil
	}

	existing, err := s.Store.FindLatestByDomains(ctx, domains, request.DNSProvider)
	if err != nil {
		return nil, err
	}
	if existing != nil && existing.ExpiresAt.After(now) {
		result.Reused = true
		if existing.CertificateName != "" {
			result.CertificateName = existing.CertificateName
		}
		result.Uploads = append(result.Uploads, issueUploadFromMetadata(existing))
		result.ExpiresAt = existing.ExpiresAt
		return result, nil
	}

	bundle, err := s.Issuer.Issue(ctx, domains, request.DNSProvider)
	if err != nil {
		return nil, err
	}

	metadata, err := s.Store.Upload(ctx, certstore.UploadRequest{
		Name:        name,
		DNSProvider: request.DNSProvider,
		Bundle:      bundle,
	})
	if err != nil {
		return nil, err
	}

	result.Uploads = append(result.Uploads, issueUploadFromMetadata(metadata))
	result.ExpiresAt = metadata.ExpiresAt
	return result, nil
}

func (s *Service) Reconcile(ctx context.Context, request config.Request) (*renewal.Result, error) {
	reconciler := &renewal.Reconciler{
		Sources:   s.Sources,
		Issuer:    s.Issuer,
		Store:     s.Store,
		Threshold: s.Threshold,
		Now:       s.now,
	}

	return reconciler.Run(ctx, request.DryRun, func(domains []string) string {
		return certutil.MakeCertificateName(s.Prefix, domains, s.now())
	})
}

func (s *Service) Smoke(ctx context.Context, request config.Request) (*SmokeResult, error) {
	componentSet := make(map[string]func(context.Context) error)
	componentSet["dns"] = s.Issuer.SmokeTest
	if s.Store != nil {
		componentSet["cas"] = s.Store.SmokeTest
	}
	for _, source := range s.Sources {
		source := source
		componentSet[source.Name()] = source.SmokeTest
	}

	components := request.Components
	if len(components) == 0 {
		components = []string{"dns", "cas"}
		for _, source := range s.Sources {
			components = append(components, source.Name())
		}
	}

	result := &SmokeResult{}
	var errs []error
	for _, component := range components {
		check, ok := componentSet[component]
		if !ok {
			err := fmt.Errorf("unknown smoke component %q", component)
			errs = append(errs, err)
			result.Checks = append(result.Checks, SmokeCheck{Name: component, OK: false, Message: err.Error()})
			continue
		}

		if err := check(ctx); err != nil {
			errs = append(errs, err)
			result.Checks = append(result.Checks, SmokeCheck{Name: component, OK: false, Message: err.Error()})
			continue
		}
		result.Checks = append(result.Checks, SmokeCheck{Name: component, OK: true})
	}

	return result, errors.Join(errs...)
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func issueUploadFromMetadata(metadata *certstore.Metadata) IssueUpload {
	if metadata == nil {
		return IssueUpload{}
	}
	return IssueUpload{
		CertificateID:   metadata.CertificateID,
		CertIdentifier:  metadata.CertIdentifier,
		CertificateName: metadata.CertificateName,
		ExpiresAt:       metadata.ExpiresAt,
	}
}
