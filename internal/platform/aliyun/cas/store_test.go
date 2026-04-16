package cas

import (
	"testing"

	cassdk "github.com/alibabacloud-go/cas-20200407/v4/client"

	"github.com/cloudcarver/autocerts/internal/config"
)

func TestDNSProviderFromDetailTags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		tags []*cassdk.GetCertificateDetailResponseBodyTags
		want config.DNSProviderType
	}{
		{
			name: "cloudflare",
			tags: []*cassdk.GetCertificateDetailResponseBodyTags{
				new(cassdk.GetCertificateDetailResponseBodyTags).SetTagKey("dns_provider").SetTagValue("cloudflare"),
			},
			want: config.DNSProviderCloudflare,
		},
		{
			name: "unknown provider value",
			tags: []*cassdk.GetCertificateDetailResponseBodyTags{
				new(cassdk.GetCertificateDetailResponseBodyTags).SetTagKey("dns_provider").SetTagValue("alidns"),
			},
			want: "",
		},
		{
			name: "ignore unrelated tag",
			tags: []*cassdk.GetCertificateDetailResponseBodyTags{
				new(cassdk.GetCertificateDetailResponseBodyTags).SetTagKey("managed_by").SetTagValue("autocerts"),
			},
			want: "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := dnsProviderFromDetailTags(tt.tags)
			if got != tt.want {
				t.Fatalf("dnsProviderFromDetailTags() = %q, want %q", got, tt.want)
			}
		})
	}
}
