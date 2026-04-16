package cas

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	cassdk "github.com/alibabacloud-go/cas-20200407/v4/client"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/utils"
	"github.com/alibabacloud-go/tea/tea"
	credential "github.com/aliyun/credentials-go/credentials"

	"github.com/cloudcarver/autocerts/internal/certstore"
	"github.com/cloudcarver/autocerts/internal/certutil"
	"github.com/cloudcarver/autocerts/internal/config"
)

const dnsProviderTagKey = "dns_provider"
const endpoint = "cas.aliyuncs.com"

type clientAPI interface {
	UploadUserCertificate(request *cassdk.UploadUserCertificateRequest) (*cassdk.UploadUserCertificateResponse, error)
	GetCertificateDetail(request *cassdk.GetCertificateDetailRequest) (*cassdk.GetCertificateDetailResponse, error)
	ListCertificates(request *cassdk.ListCertificatesRequest) (*cassdk.ListCertificatesResponse, error)
}

type Store struct {
	client          clientAPI
	resourceGroupID string

	mu    sync.RWMutex
	cache map[string]*certstore.Metadata
}

func NewStore(resourceGroupID string, credentialClient credential.Credential) (*Store, error) {
	cfg := new(openapi.Config).SetEndpoint(endpoint).SetCredential(credentialClient)
	client, err := cassdk.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("create CAS client: %w", err)
	}

	return &Store{
		client:          client,
		resourceGroupID: resourceGroupID,
		cache:           make(map[string]*certstore.Metadata),
	}, nil
}

func NewStoreWithClient(client clientAPI, resourceGroupID string) *Store {
	return &Store{
		client:          client,
		resourceGroupID: resourceGroupID,
		cache:           make(map[string]*certstore.Metadata),
	}
}

func (s *Store) Upload(_ context.Context, request certstore.UploadRequest) (*certstore.Metadata, error) {
	if request.Bundle == nil {
		return nil, fmt.Errorf("certificate bundle is required")
	}
	if request.DNSProvider == "" {
		return nil, fmt.Errorf("dns provider is required")
	}

	resourceGroupID := firstNonEmpty(request.ResourceGroupID, s.resourceGroupID)

	uploadReq := new(cassdk.UploadUserCertificateRequest).
		SetName(request.Name).
		SetCert(request.Bundle.CertificatePEM).
		SetKey(request.Bundle.PrivateKeyPEM).
		SetTags([]*cassdk.UploadUserCertificateRequestTags{
			new(cassdk.UploadUserCertificateRequestTags).
				SetKey(dnsProviderTagKey).
				SetValue(string(request.DNSProvider)),
		})
	if resourceGroupID != "" {
		uploadReq.SetResourceGroupId(resourceGroupID)
	}

	response, err := s.client.UploadUserCertificate(uploadReq)
	if err != nil {
		return nil, fmt.Errorf("upload user certificate: %w", err)
	}

	certificateID := int64(tea.Int64Value(response.Body.CertId))
	var metadata *certstore.Metadata
	for range 20 {
		metadata, err = s.getCertificateDetail(certificateID)
		if err == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.cache[metadata.CertIdentifier] = metadata
	s.mu.Unlock()

	return metadata, nil
}

func (s *Store) FindByIdentifier(_ context.Context, _ string, identifier string) (*certstore.Metadata, error) {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return nil, fmt.Errorf("certificate identifier is required")
	}

	s.mu.RLock()
	if metadata, ok := s.cache[identifier]; ok {
		s.mu.RUnlock()
		return s.enrichMetadata(metadata)
	}
	s.mu.RUnlock()

	if err := s.refreshCache(); err != nil {
		return nil, err
	}

	s.mu.RLock()
	metadata, ok := s.cache[identifier]
	s.mu.RUnlock()
	if !ok {
		return nil, &certstore.NotFoundError{Identifier: identifier}
	}
	return s.enrichMetadata(metadata)
}

func (s *Store) FindByFingerprint(_ context.Context, _ string, fingerprint string) (*certstore.Metadata, error) {
	fingerprint = strings.ToUpper(strings.TrimSpace(fingerprint))
	if fingerprint == "" {
		return nil, fmt.Errorf("certificate fingerprint is required")
	}

	if metadata := s.findCachedByFingerprint(fingerprint); metadata != nil {
		return s.enrichMetadata(metadata)
	}

	if err := s.refreshCache(); err != nil {
		return nil, err
	}

	metadata := s.findCachedByFingerprint(fingerprint)
	if metadata == nil {
		return nil, &certstore.NotFoundError{Identifier: fingerprint}
	}
	return s.enrichMetadata(metadata)
}

func (s *Store) FindLatestByDomains(_ context.Context, domains []string, provider config.DNSProviderType) (*certstore.Metadata, error) {
	if len(certutil.NormalizeDomains(domains)) == 0 {
		return nil, fmt.Errorf("certificate domains are required")
	}
	if provider == "" {
		return nil, fmt.Errorf("dns provider is required")
	}

	if metadata, err := s.findLatestCachedByDomains(domains, provider); err != nil || metadata != nil {
		return metadata, err
	}

	if err := s.refreshCache(); err != nil {
		return nil, err
	}

	return s.findLatestCachedByDomains(domains, provider)
}

func (s *Store) SmokeTest(_ context.Context) error {
	_, err := s.client.ListCertificates(new(cassdk.ListCertificatesRequest).SetCurrentPage(1).SetShowSize(1))
	if err != nil {
		return fmt.Errorf("CAS smoke test failed: %w", err)
	}
	return nil
}

func (s *Store) refreshCache() error {
	currentPage := int32(1)
	newCache := make(map[string]*certstore.Metadata)

	for {
		response, err := s.client.ListCertificates(
			new(cassdk.ListCertificatesRequest).
				SetCurrentPage(currentPage).
				SetShowSize(100),
		)
		if err != nil {
			return fmt.Errorf("list CAS certificates: %w", err)
		}

		for _, item := range response.Body.CertificateList {
			metadata := metadataFromListItem(item)
			if metadata == nil || metadata.CertIdentifier == "" {
				continue
			}
			newCache[metadata.CertIdentifier] = metadata
		}

		totalCount := tea.Int64Value(response.Body.TotalCount)
		if int64(currentPage)*100 >= totalCount || len(response.Body.CertificateList) == 0 {
			break
		}
		currentPage++
	}

	s.mu.Lock()
	s.cache = newCache
	s.mu.Unlock()
	return nil
}

func (s *Store) getCertificateDetail(certificateID int64) (*certstore.Metadata, error) {
	response, err := s.client.GetCertificateDetail(new(cassdk.GetCertificateDetailRequest).SetCertificateId(certificateID))
	if err != nil {
		return nil, fmt.Errorf("get CAS certificate detail %d: %w", certificateID, err)
	}

	body := response.Body
	return &certstore.Metadata{
		CertificateID:   int64(tea.Int32Value(body.CertificateId)),
		CertIdentifier:  tea.StringValue(body.CertIdentifier),
		CertificateName: tea.StringValue(body.CertificateName),
		DNSProvider:     dnsProviderFromDetailTags(body.Tags),
		Fingerprint:     strings.ToUpper(tea.StringValue(body.FingerPrint)),
		Domains:         certutil.NormalizeDomains(append([]string{tea.StringValue(body.CommonName)}, pointerStrings(body.SubjectAlternativeNames)...)),
		ExpiresAt:       certutil.ParseAlibabaTime(tea.Int64Value(body.NotAfter)),
		Source:          tea.StringValue(body.CertificateSource),
	}, nil
}

func metadataFromListItem(item *cassdk.ListCertificatesResponseBodyCertificateList) *certstore.Metadata {
	if item == nil {
		return nil
	}

	certificateID, _ := strconv.ParseInt(tea.StringValue(item.CertificateId), 10, 64)
	return &certstore.Metadata{
		CertificateID:   certificateID,
		CertIdentifier:  tea.StringValue(item.CertIdentifier),
		CertificateName: tea.StringValue(item.CertificateName),
		Fingerprint:     strings.ToUpper(tea.StringValue(item.FingerPrint)),
		Domains:         certutil.NormalizeDomains(append([]string{tea.StringValue(item.CommonName)}, pointerStrings(item.SubjectAlternativeNames)...)),
		ExpiresAt:       certutil.ParseAlibabaTime(tea.Int64Value(item.NotAfter)),
		Source:          tea.StringValue(item.CertificateSource),
	}
}

func (s *Store) enrichMetadata(metadata *certstore.Metadata) (*certstore.Metadata, error) {
	if metadata == nil {
		return nil, fmt.Errorf("certificate metadata is required")
	}
	if metadata.DNSProvider != "" || metadata.CertificateID == 0 {
		return metadata, nil
	}

	detail, err := s.getCertificateDetail(metadata.CertificateID)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.cache[detail.CertIdentifier] = detail
	s.mu.Unlock()
	return detail, nil
}

func (s *Store) findCachedByFingerprint(fingerprint string) *certstore.Metadata {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, metadata := range s.cache {
		if metadata == nil {
			continue
		}
		if strings.ToUpper(strings.TrimSpace(metadata.Fingerprint)) == fingerprint {
			return metadata
		}
	}
	return nil
}

func (s *Store) findLatestCachedByDomains(domains []string, provider config.DNSProviderType) (*certstore.Metadata, error) {
	expected := strings.Join(certutil.SortDomains(domains), ",")
	if expected == "" {
		return nil, nil
	}

	s.mu.RLock()
	candidates := make([]*certstore.Metadata, 0, len(s.cache))
	for _, metadata := range s.cache {
		if metadata == nil {
			continue
		}
		if strings.Join(certutil.SortDomains(metadata.Domains), ",") != expected {
			continue
		}
		candidates = append(candidates, metadata)
	}
	s.mu.RUnlock()

	slices.SortFunc(candidates, func(a, b *certstore.Metadata) int {
		if byExpiry := cmp.Compare(b.ExpiresAt.Unix(), a.ExpiresAt.Unix()); byExpiry != 0 {
			return byExpiry
		}
		return cmp.Compare(b.CertificateID, a.CertificateID)
	})

	for _, metadata := range candidates {
		enriched, err := s.enrichMetadata(metadata)
		if err != nil {
			return nil, err
		}
		if enriched != nil && enriched.DNSProvider == provider {
			return enriched, nil
		}
	}
	return nil, nil
}

func dnsProviderFromDetailTags(tags []*cassdk.GetCertificateDetailResponseBodyTags) config.DNSProviderType {
	for _, tag := range tags {
		if tag == nil {
			continue
		}
		if strings.TrimSpace(tea.StringValue(tag.TagKey)) != dnsProviderTagKey {
			continue
		}

		provider, err := config.ParseDNSProvider(tea.StringValue(tag.TagValue))
		if err != nil {
			return ""
		}
		return provider
	}
	return ""
}

func pointerStrings(values []*string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == nil {
			continue
		}
		out = append(out, tea.StringValue(value))
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
