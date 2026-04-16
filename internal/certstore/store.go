package certstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cloudcarver/autocerts/internal/certutil"
	"github.com/cloudcarver/autocerts/internal/config"
)

type Metadata struct {
	Region          string                 `json:"region,omitempty"`
	CertificateID   int64                  `json:"certificateId"`
	CertIdentifier  string                 `json:"certIdentifier"`
	CertificateName string                 `json:"certificateName"`
	DNSProvider     config.DNSProviderType `json:"dnsProvider,omitempty"`
	Fingerprint     string                 `json:"fingerprint"`
	Domains         []string               `json:"domains"`
	ExpiresAt       time.Time              `json:"expiresAt"`
	Source          string                 `json:"source,omitempty"`
}

type UploadRequest struct {
	Region          string
	Name            string
	DNSProvider     config.DNSProviderType
	Bundle          *certutil.Bundle
	ResourceGroupID string
}

type NotFoundError struct {
	Identifier string
}

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("certificate %q not found in CAS", e.Identifier)
}

func IsNotFound(err error) bool {
	var target *NotFoundError
	return errors.As(err, &target)
}

type Store interface {
	Upload(ctx context.Context, request UploadRequest) (*Metadata, error)
	FindByIdentifier(ctx context.Context, region, identifier string) (*Metadata, error)
	FindByFingerprint(ctx context.Context, region, fingerprint string) (*Metadata, error)
	FindLatestByDomains(ctx context.Context, domains []string, provider config.DNSProviderType) (*Metadata, error)
	SmokeTest(ctx context.Context) error
}
