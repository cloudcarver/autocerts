package target

import (
	"context"
	"time"

	"github.com/cloudcarver/autocerts/internal/certutil"
)

type Material struct {
	Bundle          *certutil.Bundle
	CertificateID   int64
	CertIdentifier  string
	CertificateName string
}

type Binding interface {
	ResourceType() string
	DisplayName() string
	Region() string
	Domains() []string
	ExpiresAt() time.Time
	Fingerprint() string
	Replace(ctx context.Context, material Material) error
}

type Source interface {
	Name() string
	Discover(ctx context.Context) ([]Binding, error)
	SmokeTest(ctx context.Context) error
}
