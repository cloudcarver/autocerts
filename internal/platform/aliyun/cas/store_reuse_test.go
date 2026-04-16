package cas

import (
	"context"
	"testing"
	"time"

	cassdk "github.com/alibabacloud-go/cas-20200407/v4/client"
	"github.com/alibabacloud-go/tea/tea"

	"github.com/cloudcarver/autocerts/internal/config"
)

func TestFindLatestByDomainsUsesExactDomainSetAndProvider(t *testing.T) {
	t.Parallel()

	client := &storeClientStub{
		listResponse: &cassdk.ListCertificatesResponse{
			Body: new(cassdk.ListCertificatesResponseBody).
				SetTotalCount(3).
				SetCertificateList([]*cassdk.ListCertificatesResponseBodyCertificateList{
					new(cassdk.ListCertificatesResponseBodyCertificateList).
						SetCertificateId("100").
						SetCertIdentifier("100-global").
						SetCertificateName("newer-aliyun").
						SetCommonName("example.com").
						SetSubjectAlternativeNames([]*string{stringPtr("*.example.com")}).
						SetNotAfter(time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC).UnixMilli()),
					new(cassdk.ListCertificatesResponseBodyCertificateList).
						SetCertificateId("99").
						SetCertIdentifier("99-global").
						SetCertificateName("newer-cloudflare").
						SetCommonName("example.com").
						SetSubjectAlternativeNames([]*string{stringPtr("*.example.com")}).
						SetNotAfter(time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC).UnixMilli()),
					new(cassdk.ListCertificatesResponseBodyCertificateList).
						SetCertificateId("98").
						SetCertIdentifier("98-global").
						SetCertificateName("different-domains").
						SetCommonName("api.example.com").
						SetNotAfter(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC).UnixMilli()),
				}),
		},
		details: map[int64]*cassdk.GetCertificateDetailResponse{
			100: {
				Body: new(cassdk.GetCertificateDetailResponseBody).
					SetCertificateId(100).
					SetCertIdentifier("100-global").
					SetCertificateName("newer-aliyun").
					SetCommonName("example.com").
					SetSubjectAlternativeNames([]*string{stringPtr("*.example.com")}).
					SetFingerPrint("fp-100").
					SetNotAfter(time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC).UnixMilli()).
					SetTags([]*cassdk.GetCertificateDetailResponseBodyTags{
						new(cassdk.GetCertificateDetailResponseBodyTags).SetTagKey("dns_provider").SetTagValue("aliyun"),
					}),
			},
			99: {
				Body: new(cassdk.GetCertificateDetailResponseBody).
					SetCertificateId(99).
					SetCertIdentifier("99-global").
					SetCertificateName("newer-cloudflare").
					SetCommonName("example.com").
					SetSubjectAlternativeNames([]*string{stringPtr("*.example.com")}).
					SetFingerPrint("fp-99").
					SetNotAfter(time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC).UnixMilli()).
					SetTags([]*cassdk.GetCertificateDetailResponseBodyTags{
						new(cassdk.GetCertificateDetailResponseBodyTags).SetTagKey("dns_provider").SetTagValue("cloudflare"),
					}),
			},
		},
	}
	store := NewStoreWithClient(client, "")

	metadata, err := store.FindLatestByDomains(context.Background(), []string{"*.example.com", "example.com"}, config.DNSProviderCloudflare)
	if err != nil {
		t.Fatalf("FindLatestByDomains returned error: %v", err)
	}
	if metadata == nil {
		t.Fatalf("expected metadata, got nil")
	}
	if metadata.CertIdentifier != "99-global" {
		t.Fatalf("unexpected metadata: %#v", metadata)
	}
}

type storeClientStub struct {
	listResponse *cassdk.ListCertificatesResponse
	details      map[int64]*cassdk.GetCertificateDetailResponse
}

func (s *storeClientStub) UploadUserCertificate(_ *cassdk.UploadUserCertificateRequest) (*cassdk.UploadUserCertificateResponse, error) {
	return nil, nil
}

func (s *storeClientStub) GetCertificateDetail(request *cassdk.GetCertificateDetailRequest) (*cassdk.GetCertificateDetailResponse, error) {
	return s.details[tea.Int64Value(request.GetCertificateId())], nil
}

func (s *storeClientStub) ListCertificates(_ *cassdk.ListCertificatesRequest) (*cassdk.ListCertificatesResponse, error) {
	return s.listResponse, nil
}

func stringPtr(value string) *string {
	return &value
}
