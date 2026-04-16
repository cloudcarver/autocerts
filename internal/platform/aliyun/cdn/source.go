package cdn

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	cdnsdk "github.com/alibabacloud-go/cdn-20180510/client"
	openapi "github.com/alibabacloud-go/darabonba-openapi/client"
	credential "github.com/aliyun/credentials-go/credentials"

	"github.com/alibabacloud-go/tea/tea"
	"github.com/cloudcarver/autocerts/internal/certutil"
	"github.com/cloudcarver/autocerts/internal/target"
)

const endpoint = "cdn.aliyuncs.com"
const serviceRegion = "cn-hangzhou"

type clientAPI interface {
	DescribeCdnHttpsDomainList(request *cdnsdk.DescribeCdnHttpsDomainListRequest) (*cdnsdk.DescribeCdnHttpsDomainListResponse, error)
	DescribeDomainCertificateInfo(request *cdnsdk.DescribeDomainCertificateInfoRequest) (*cdnsdk.DescribeDomainCertificateInfoResponse, error)
	SetDomainServerCertificate(request *cdnsdk.SetDomainServerCertificateRequest) (*cdnsdk.SetDomainServerCertificateResponse, error)
}

type Source struct {
	client clientAPI
}

func NewSource(credentialClient credential.Credential) (*Source, error) {
	cfg := new(openapi.Config).
		SetEndpoint(endpoint).
		SetRegionId(serviceRegion).
		SetCredential(credentialClient)
	client, err := cdnsdk.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("create CDN client: %w", err)
	}
	return NewSourceWithClient(client), nil
}

func NewSourceWithClient(client clientAPI) *Source {
	return &Source{client: client}
}

func (s *Source) Name() string {
	return "cdn"
}

func (s *Source) Discover(ctx context.Context) ([]target.Binding, error) {
	var (
		bindings []target.Binding
		errs     []error
		page     int32 = 1
	)

	for {
		select {
		case <-ctx.Done():
			return bindings, ctx.Err()
		default:
		}

		response, err := s.client.DescribeCdnHttpsDomainList(
			new(cdnsdk.DescribeCdnHttpsDomainListRequest).
				SetPageNumber(page).
				SetPageSize(100),
		)
		if err != nil {
			return bindings, fmt.Errorf("list CDN https domains: %w", err)
		}

		items := certificateSummaries(response)
		for _, item := range items {
			domainName := strings.TrimSpace(tea.StringValue(item.DomainName))
			if domainName == "" {
				continue
			}

			binding, err := s.discoverBinding(domainName)
			warnings, hardErr := target.SplitWarnings(err)
			for _, warning := range warnings {
				errs = append(errs, target.Warningf("discover CDN domain %s: %s", domainName, warning))
			}
			if hardErr != nil {
				errs = append(errs, fmt.Errorf("discover CDN domain %s: %w", domainName, hardErr))
				continue
			}
			if binding != nil {
				bindings = append(bindings, binding)
			}
		}

		totalCount := httpsDomainTotalCount(response)
		if len(items) == 0 || page*100 >= totalCount {
			break
		}
		page++
	}

	return bindings, errors.Join(errs...)
}

func (s *Source) SmokeTest(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	_, err := s.client.DescribeCdnHttpsDomainList(
		new(cdnsdk.DescribeCdnHttpsDomainListRequest).
			SetPageNumber(1).
			SetPageSize(1),
	)
	if err != nil {
		return fmt.Errorf("CDN smoke test failed: %w", err)
	}
	return nil
}

func (s *Source) discoverBinding(domainName string) (*binding, error) {
	info, err := s.describeCurrentCertificate(domainName)
	if err != nil {
		return nil, err
	}
	if info == nil {
		return nil, target.Warningf("current certificate info is empty")
	}

	certificatePEM := strings.TrimSpace(tea.StringValue(info.ServerCertificate))
	if certificatePEM == "" {
		return nil, target.Warningf("current certificate PEM is empty")
	}

	bundle, err := certutil.BundleFromPEM(nil, certificatePEM, "")
	if err != nil {
		return nil, target.Warningf("parse current certificate: %v", err)
	}

	domains := bundle.Domains
	if len(domains) == 0 {
		domains = []string{domainName}
	}

	return &binding{
		client:      s.client,
		domainName:  domainName,
		domains:     domains,
		expiresAt:   firstNonZeroTime(bundle.ExpiresAt, parseCDNTime(tea.StringValue(info.CertExpireTime))),
		fingerprint: bundle.Fingerprint,
	}, nil
}

func (s *Source) describeCurrentCertificate(domainName string) (*cdnsdk.DescribeDomainCertificateInfoResponseBodyCertInfosCertInfo, error) {
	response, err := s.client.DescribeDomainCertificateInfo(
		new(cdnsdk.DescribeDomainCertificateInfoRequest).
			SetDomainName(domainName),
	)
	if err != nil {
		return nil, fmt.Errorf("describe CDN certificate info: %w", err)
	}
	return selectCurrentCertificateInfo(domainName, certificateDetails(response)), nil
}

type binding struct {
	client      clientAPI
	domainName  string
	domains     []string
	expiresAt   time.Time
	fingerprint string
}

func (b *binding) ResourceType() string {
	return "cdn"
}

func (b *binding) DisplayName() string {
	return fmt.Sprintf("cdn %s", b.domainName)
}

func (b *binding) Region() string {
	return ""
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

func (b *binding) Replace(ctx context.Context, material target.Material) error {
	if material.Bundle == nil {
		return fmt.Errorf("certificate bundle is required")
	}

	_, err := b.client.SetDomainServerCertificate(
		new(cdnsdk.SetDomainServerCertificateRequest).
			SetDomainName(b.domainName).
			SetServerCertificateStatus("on").
			SetCertType("upload").
			SetCertName(material.CertificateName).
			SetServerCertificate(material.Bundle.CertificatePEM).
			SetPrivateKey(material.Bundle.PrivateKeyPEM).
			SetForceSet("1"),
	)
	if err != nil {
		return fmt.Errorf("update CDN domain certificate %s: %w", b.domainName, err)
	}

	return waitFor(ctx, 2*time.Minute, 3*time.Second, func() (bool, error) {
		info, err := b.describeCurrentCertificate()
		if err != nil {
			return false, err
		}
		if info == nil || strings.TrimSpace(tea.StringValue(info.ServerCertificate)) == "" {
			return false, nil
		}
		current, err := certutil.BundleFromPEM(nil, tea.StringValue(info.ServerCertificate), "")
		if err != nil {
			return false, err
		}
		return current.Fingerprint == material.Bundle.Fingerprint, nil
	})
}

func (b *binding) describeCurrentCertificate() (*cdnsdk.DescribeDomainCertificateInfoResponseBodyCertInfosCertInfo, error) {
	response, err := b.client.DescribeDomainCertificateInfo(
		new(cdnsdk.DescribeDomainCertificateInfoRequest).
			SetDomainName(b.domainName),
	)
	if err != nil {
		return nil, fmt.Errorf("describe CDN certificate info for %s: %w", b.domainName, err)
	}
	return selectCurrentCertificateInfo(b.domainName, certificateDetails(response)), nil
}

func selectCurrentCertificateInfo(domainName string, items []*cdnsdk.DescribeDomainCertificateInfoResponseBodyCertInfosCertInfo) *cdnsdk.DescribeDomainCertificateInfoResponseBodyCertInfosCertInfo {
	var (
		best      *cdnsdk.DescribeDomainCertificateInfoResponseBodyCertInfosCertInfo
		bestScore = -1
	)

	for _, item := range items {
		if item == nil {
			continue
		}
		score := 0
		if strings.EqualFold(strings.TrimSpace(tea.StringValue(item.DomainName)), strings.TrimSpace(domainName)) {
			score += 4
		}
		if strings.EqualFold(strings.TrimSpace(tea.StringValue(item.ServerCertificateStatus)), "on") {
			score += 4
		}
		if strings.EqualFold(strings.TrimSpace(tea.StringValue(item.Status)), "success") {
			score += 2
		}
		if strings.TrimSpace(tea.StringValue(item.ServerCertificate)) != "" {
			score++
		}
		if score > bestScore {
			best = item
			bestScore = score
		}
	}

	return best
}

func firstNonZeroTime(values ...time.Time) time.Time {
	for _, value := range values {
		if !value.IsZero() {
			return value.UTC()
		}
	}
	return time.Time{}
}

func parseCDNTime(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}

	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}

func certificateSummaries(response *cdnsdk.DescribeCdnHttpsDomainListResponse) []*cdnsdk.DescribeCdnHttpsDomainListResponseBodyCertInfosCertInfo {
	if response == nil || response.Body == nil || response.Body.CertInfos == nil {
		return nil
	}
	return response.Body.CertInfos.CertInfo
}

func certificateDetails(response *cdnsdk.DescribeDomainCertificateInfoResponse) []*cdnsdk.DescribeDomainCertificateInfoResponseBodyCertInfosCertInfo {
	if response == nil || response.Body == nil || response.Body.CertInfos == nil {
		return nil
	}
	return response.Body.CertInfos.CertInfo
}

func httpsDomainTotalCount(response *cdnsdk.DescribeCdnHttpsDomainListResponse) int32 {
	if response == nil || response.Body == nil {
		return 0
	}
	return tea.Int32Value(response.Body.TotalCount)
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
