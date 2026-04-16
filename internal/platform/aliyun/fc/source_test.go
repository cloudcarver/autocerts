package fc

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"testing"

	fcsdk "github.com/alibabacloud-go/fc-open-20210406/v2/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"

	"github.com/cloudcarver/autocerts/internal/target"
)

func TestDiscoverSkipsUnavailableRegionEndpoint(t *testing.T) {
	t.Parallel()

	var shenzhenListed bool

	source := NewSourceWithFactory(
		[]string{"cn-guangzhou", "cn-shenzhen"},
		"1323799728031501",
		nil,
		func(region, accountID string) (clientAPI, error) {
			switch region {
			case "cn-guangzhou":
				return &sourceClientStub{
					listErr: &url.Error{
						Op:  "Get",
						URL: "https://" + accountID + "." + region + ".fc.aliyuncs.com/2021-04-06/custom-domains?limit=100",
						Err: &net.DNSError{Err: "no such host", Name: accountID + "." + region + ".fc.aliyuncs.com", IsNotFound: true},
					},
				}, nil
			case "cn-shenzhen":
				return &sourceClientStub{
					listFunc: func(*fcsdk.ListCustomDomainsRequest, *fcsdk.ListCustomDomainsHeaders, *util.RuntimeOptions) (*fcsdk.ListCustomDomainsResponse, error) {
						shenzhenListed = true
						return &fcsdk.ListCustomDomainsResponse{
							Body: &fcsdk.ListCustomDomainsResponseBody{},
						}, nil
					},
				}, nil
			default:
				return nil, errors.New("unexpected region")
			}
		},
	)

	bindings, err := source.Discover(context.Background())
	if len(bindings) != 0 {
		t.Fatalf("expected no bindings, got %d", len(bindings))
	}
	if !shenzhenListed {
		t.Fatalf("expected cn-shenzhen to still be scanned")
	}

	warnings, hardErr := target.SplitWarnings(err)
	if hardErr != nil {
		t.Fatalf("expected warning-only error, got %v", hardErr)
	}
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %#v", len(warnings), warnings)
	}
	if got := warnings[0]; got == "" || !strings.Contains(got, "cn-guangzhou") || !strings.Contains(got, "endpoint unavailable") {
		t.Fatalf("unexpected warning: %q", got)
	}
}

type sourceClientStub struct {
	listFunc func(*fcsdk.ListCustomDomainsRequest, *fcsdk.ListCustomDomainsHeaders, *util.RuntimeOptions) (*fcsdk.ListCustomDomainsResponse, error)
	listErr  error
}

func (s *sourceClientStub) ListCustomDomainsWithOptions(request *fcsdk.ListCustomDomainsRequest, headers *fcsdk.ListCustomDomainsHeaders, runtime *util.RuntimeOptions) (*fcsdk.ListCustomDomainsResponse, error) {
	if s.listFunc != nil {
		return s.listFunc(request, headers, runtime)
	}
	return nil, s.listErr
}

func (s *sourceClientStub) GetCustomDomainWithOptions(domainName *string, headers *fcsdk.GetCustomDomainHeaders, runtime *util.RuntimeOptions) (*fcsdk.GetCustomDomainResponse, error) {
	return &fcsdk.GetCustomDomainResponse{
		Body: &fcsdk.GetCustomDomainResponseBody{
			DomainName: domainName,
		},
	}, nil
}

func (s *sourceClientStub) UpdateCustomDomainWithOptions(domainName *string, request *fcsdk.UpdateCustomDomainRequest, headers *fcsdk.UpdateCustomDomainHeaders, runtime *util.RuntimeOptions) (*fcsdk.UpdateCustomDomainResponse, error) {
	return &fcsdk.UpdateCustomDomainResponse{
		Headers: map[string]*string{"x-request-id": tea.String("test")},
	}, nil
}
