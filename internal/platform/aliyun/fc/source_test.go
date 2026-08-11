package fc

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"testing"

	fcsdk "github.com/alibabacloud-go/fc-20230330/v4/client"
	"github.com/alibabacloud-go/tea/dara"
	"github.com/alibabacloud-go/tea/tea"

	"github.com/cloudcarver/autocerts/internal/certutil"
	"github.com/cloudcarver/autocerts/internal/target"
)

func TestDiscoverSkipsUnavailableRegionEndpoint(t *testing.T) {
	t.Parallel()

	var shenzhenListed bool

	source := NewSourceWithFactory(
		[]string{"cn-guangzhou", "cn-shenzhen"},
		func(region string) (clientAPI, error) {
			switch region {
			case "cn-guangzhou":
				return &sourceClientStub{
					listErr: &url.Error{
						Op:  "Get",
						URL: "https://fcv3." + region + ".aliyuncs.com/2023-03-30/custom-domains?limit=100",
						Err: &net.DNSError{Err: "no such host", Name: "fcv3." + region + ".aliyuncs.com", IsNotFound: true},
					},
				}, nil
			case "cn-shenzhen":
				return &sourceClientStub{
					listFunc: func(*fcsdk.ListCustomDomainsRequest, map[string]*string, *dara.RuntimeOptions) (*fcsdk.ListCustomDomainsResponse, error) {
						shenzhenListed = true
						return &fcsdk.ListCustomDomainsResponse{
							Body: &fcsdk.ListCustomDomainOutput{},
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

func TestUpdateRequestUsesFCV3ShapeAndPreservesConfiguration(t *testing.T) {
	t.Parallel()

	authConfig := new(fcsdk.AuthConfig).SetAuthType("anonymous")
	corsConfig := new(fcsdk.CORSConfig).SetAllowOrigins([]*string{tea.String("https://example.com")})
	routeConfig := new(fcsdk.RouteConfig).SetRoutes([]*fcsdk.PathConfig{
		new(fcsdk.PathConfig).
			SetFunctionName("registry").
			SetPath("/*").
			SetQualifier("LATEST"),
	})
	tlsConfig := new(fcsdk.TLSConfig).SetMinVersion("TLSv1.2")
	wafConfig := new(fcsdk.WAFConfig).SetEnableWAF(false)

	b := &binding{
		protocol:    "HTTP,HTTPS",
		authConfig:  authConfig,
		corsConfig:  corsConfig,
		routeConfig: routeConfig,
		tlsConfig:   tlsConfig,
		wafConfig:   wafConfig,
	}
	request := b.updateRequest(target.Material{
		CertificateName: "renewed-cert",
		Bundle: &certutil.Bundle{
			CertificatePEM: "certificate-pem",
			PrivateKeyPEM:  "private-key-pem",
		},
	})

	if request == nil || request.Body == nil {
		t.Fatal("expected FC v3 request body")
	}
	if request.Body.AuthConfig != authConfig || request.Body.CorsConfig != corsConfig || request.Body.RouteConfig != routeConfig || request.Body.TlsConfig != tlsConfig || request.Body.WafConfig != wafConfig {
		t.Fatal("expected existing custom-domain configuration to be preserved")
	}
	if got := tea.StringValue(request.Body.Protocol); got != "HTTP,HTTPS" {
		t.Fatalf("unexpected protocol: %q", got)
	}
	if request.Body.CertConfig == nil || tea.StringValue(request.Body.CertConfig.CertName) != "renewed-cert" || tea.StringValue(request.Body.CertConfig.Certificate) != "certificate-pem" || tea.StringValue(request.Body.CertConfig.PrivateKey) != "private-key-pem" {
		t.Fatalf("unexpected certificate config: %#v", request.Body.CertConfig)
	}
	if got := tea.StringValue(request.Body.RouteConfig.Routes[0].FunctionName); got != "registry" {
		t.Fatalf("unexpected function name: %q", got)
	}
}

type sourceClientStub struct {
	listFunc func(*fcsdk.ListCustomDomainsRequest, map[string]*string, *dara.RuntimeOptions) (*fcsdk.ListCustomDomainsResponse, error)
	listErr  error
}

func (s *sourceClientStub) ListCustomDomainsWithOptions(request *fcsdk.ListCustomDomainsRequest, headers map[string]*string, runtime *dara.RuntimeOptions) (*fcsdk.ListCustomDomainsResponse, error) {
	if s.listFunc != nil {
		return s.listFunc(request, headers, runtime)
	}
	return nil, s.listErr
}

func (s *sourceClientStub) GetCustomDomainWithOptions(domainName *string, _ map[string]*string, _ *dara.RuntimeOptions) (*fcsdk.GetCustomDomainResponse, error) {
	return &fcsdk.GetCustomDomainResponse{
		Body: &fcsdk.CustomDomain{
			DomainName: domainName,
		},
	}, nil
}

func (s *sourceClientStub) UpdateCustomDomainWithOptions(_ *string, _ *fcsdk.UpdateCustomDomainRequest, _ map[string]*string, _ *dara.RuntimeOptions) (*fcsdk.UpdateCustomDomainResponse, error) {
	return &fcsdk.UpdateCustomDomainResponse{
		Headers: map[string]*string{"x-request-id": tea.String("test")},
	}, nil
}
