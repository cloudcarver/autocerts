package oss

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	osssdk "github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"

	"github.com/cloudcarver/autocerts/internal/certstore"
	"github.com/cloudcarver/autocerts/internal/certutil"
	"github.com/cloudcarver/autocerts/internal/config"
	"github.com/cloudcarver/autocerts/internal/platform/aliyun/auth"
	"github.com/cloudcarver/autocerts/internal/target"
)

type catalog interface {
	FindByIdentifier(ctx context.Context, region, identifier string) (*certstore.Metadata, error)
}

type serviceClientAPI interface {
	ListBuckets(ctx context.Context, request *osssdk.ListBucketsRequest, optFns ...func(*osssdk.Options)) (*osssdk.ListBucketsResult, error)
}

type bucketClientAPI interface {
	ListCname(ctx context.Context, request *osssdk.ListCnameRequest, optFns ...func(*osssdk.Options)) (*osssdk.ListCnameResult, error)
	PutCname(ctx context.Context, request *osssdk.PutCnameRequest, optFns ...func(*osssdk.Options)) (*osssdk.PutCnameResult, error)
}

type bucketClientFactory func(region string) (bucketClientAPI, error)

const serviceRegion = "cn-hangzhou"

type Source struct {
	serviceClient serviceClientAPI
	catalog       catalog
	factory       bucketClientFactory
}

func NewSource(authProvider *auth.Provider, certCatalog catalog) *Source {
	serviceConfig := osssdk.LoadDefaultConfig().
		WithRegion(serviceRegion).
		WithCredentialsProvider(authProvider.OSSCredentialsProvider())
	serviceClient := osssdk.NewClient(serviceConfig)

	var (
		mu      sync.Mutex
		clients = make(map[string]bucketClientAPI)
	)

	return &Source{
		serviceClient: serviceClient,
		catalog:       certCatalog,
		factory: func(region string) (bucketClientAPI, error) {
			mu.Lock()
			defer mu.Unlock()
			if client, ok := clients[region]; ok {
				return client, nil
			}

			cfg := osssdk.LoadDefaultConfig().
				WithRegion(region).
				WithCredentialsProvider(authProvider.OSSCredentialsProvider())
			client := osssdk.NewClient(cfg)
			clients[region] = client
			return client, nil
		},
	}
}

func NewSourceWithClients(serviceClient serviceClientAPI, certCatalog catalog, factory bucketClientFactory) *Source {
	return &Source{
		serviceClient: serviceClient,
		catalog:       certCatalog,
		factory:       factory,
	}
}

func (s *Source) Name() string {
	return "oss"
}

func (s *Source) Discover(ctx context.Context) ([]target.Binding, error) {
	var (
		bindings []target.Binding
		errs     []error
		marker   *string
	)

	for {
		result, err := s.serviceClient.ListBuckets(ctx, &osssdk.ListBucketsRequest{Marker: marker, MaxKeys: 100})
		if err != nil {
			return nil, fmt.Errorf("list OSS buckets: %w", err)
		}

		for _, bucket := range result.Buckets {
			bucketName := osssdk.ToString(bucket.Name)
			region := firstNonEmpty(osssdk.ToString(bucket.Region), osssdk.ToString(bucket.Location))
			if bucketName == "" || region == "" {
				continue
			}

			client, err := s.factory(region)
			if err != nil {
				errs = append(errs, fmt.Errorf("create OSS client for %s: %w", region, err))
				continue
			}

			cnames, err := client.ListCname(ctx, &osssdk.ListCnameRequest{Bucket: osssdk.Ptr(bucketName)})
			if err != nil {
				errs = append(errs, fmt.Errorf("list bucket CNAME for %s/%s: %w", region, bucketName, err))
				continue
			}

			for _, cname := range cnames.Cnames {
				if cname.Certificate == nil {
					continue
				}

				identifier := strings.TrimSpace(osssdk.ToString(cname.Certificate.CertId))
				if identifier == "" {
					continue
				}

				metadata, err := s.catalog.FindByIdentifier(ctx, region, identifier)
				if err != nil {
					if certstore.IsNotFound(err) {
						errs = append(errs, target.Warningf("resolve OSS certificate %s for %s/%s: %v", identifier, region, bucketName, err))
						continue
					}
					errs = append(errs, fmt.Errorf("resolve OSS certificate %s for %s/%s: %w", identifier, region, bucketName, err))
					continue
				}

				expiresAt := metadata.ExpiresAt
				if expiresAt.IsZero() {
					expiresAt, _ = certutil.ParseOSSRFC1123(osssdk.ToString(cname.Certificate.ValidEndDate))
				}

				domains := metadata.Domains
				if len(domains) == 0 {
					domains = []string{osssdk.ToString(cname.Domain)}
				}

				bindings = append(bindings, &binding{
					client:        client,
					region:        region,
					bucketName:    bucketName,
					domain:        osssdk.ToString(cname.Domain),
					currentCertID: identifier,
					dnsProvider:   metadata.DNSProvider,
					domains:       domains,
					expiresAt:     expiresAt,
					fingerprint:   firstNonEmpty(metadata.Fingerprint, strings.ToUpper(osssdk.ToString(cname.Certificate.Fingerprint))),
				})
			}
		}

		if !result.IsTruncated || result.NextMarker == nil {
			break
		}
		marker = result.NextMarker
	}

	return bindings, errors.Join(errs...)
}

func (s *Source) SmokeTest(ctx context.Context) error {
	_, err := s.serviceClient.ListBuckets(ctx, &osssdk.ListBucketsRequest{MaxKeys: 1})
	if err != nil {
		return fmt.Errorf("OSS smoke test failed: %w", err)
	}
	return nil
}

type binding struct {
	client        bucketClientAPI
	region        string
	bucketName    string
	domain        string
	currentCertID string
	dnsProvider   config.DNSProviderType
	domains       []string
	expiresAt     time.Time
	fingerprint   string
}

func (b *binding) ResourceType() string {
	return "oss"
}

func (b *binding) DisplayName() string {
	return fmt.Sprintf("oss[%s] %s -> %s", b.region, b.bucketName, b.domain)
}

func (b *binding) Region() string {
	return b.region
}

func (b *binding) Domains() []string {
	return append([]string(nil), b.domains...)
}

func (b *binding) ExpiresAt() time.Time {
	return b.expiresAt
}

func (b *binding) Fingerprint() string {
	return b.fingerprint
}

func (b *binding) DNSProvider() config.DNSProviderType {
	return b.dnsProvider
}

func (b *binding) Replace(ctx context.Context, material target.Material) error {
	if material.CertIdentifier == "" {
		return fmt.Errorf("CAS cert identifier is required")
	}
	if material.CertIdentifier == b.currentCertID {
		return nil
	}

	_, err := b.client.PutCname(ctx, &osssdk.PutCnameRequest{
		Bucket: osssdk.Ptr(b.bucketName),
		BucketCnameConfiguration: &osssdk.BucketCnameConfiguration{
			Cname: &osssdk.Cname{
				Domain: osssdk.Ptr(b.domain),
				CertificateConfiguration: &osssdk.CertificateConfiguration{
					CertId:         osssdk.Ptr(material.CertIdentifier),
					PreviousCertId: osssdk.Ptr(b.currentCertID),
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("update OSS CNAME certificate: %w", err)
	}

	return waitFor(ctx, 2*time.Minute, 3*time.Second, func() (bool, error) {
		result, err := b.client.ListCname(ctx, &osssdk.ListCnameRequest{Bucket: osssdk.Ptr(b.bucketName)})
		if err != nil {
			return false, err
		}

		for _, cname := range result.Cnames {
			if osssdk.ToString(cname.Domain) != b.domain || cname.Certificate == nil {
				continue
			}
			return osssdk.ToString(cname.Certificate.CertId) == material.CertIdentifier, nil
		}
		return false, nil
	})
}

func waitFor(ctx context.Context, timeout, interval time.Duration, check func() (bool, error)) error {
	deadline := time.Now().Add(timeout)
	for {
		done, err := check()
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s", timeout)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
