package fc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/utils"
	fcsdk "github.com/alibabacloud-go/fc-20230330/v4/client"
	"github.com/alibabacloud-go/tea/dara"
	"github.com/alibabacloud-go/tea/tea"
	credential "github.com/aliyun/credentials-go/credentials"

	"github.com/cloudcarver/autocerts/internal/certutil"
	"github.com/cloudcarver/autocerts/internal/target"
)

type clientAPI interface {
	ListCustomDomainsWithOptions(request *fcsdk.ListCustomDomainsRequest, headers map[string]*string, runtime *dara.RuntimeOptions) (*fcsdk.ListCustomDomainsResponse, error)
	GetCustomDomainWithOptions(domainName *string, headers map[string]*string, runtime *dara.RuntimeOptions) (*fcsdk.GetCustomDomainResponse, error)
	UpdateCustomDomainWithOptions(domainName *string, request *fcsdk.UpdateCustomDomainRequest, headers map[string]*string, runtime *dara.RuntimeOptions) (*fcsdk.UpdateCustomDomainResponse, error)
}

type clientFactory func(region string) (clientAPI, error)

type Source struct {
	regions []string
	factory clientFactory
}

func NewSource(regions []string, credentialClient credential.Credential) *Source {
	var (
		mu      sync.Mutex
		clients = make(map[string]clientAPI)
	)

	return &Source{
		regions: regions,
		factory: func(region string) (clientAPI, error) {
			mu.Lock()
			defer mu.Unlock()
			if client, ok := clients[region]; ok {
				return client, nil
			}

			cfg := new(openapi.Config).
				SetRegionId(region).
				SetCredential(credentialClient)
			client, err := fcsdk.NewClient(cfg)
			if err != nil {
				return nil, fmt.Errorf("create FC client for %s: %w", region, err)
			}
			clients[region] = client
			return client, nil
		},
	}
}

func NewSourceWithFactory(regions []string, factory clientFactory) *Source {
	return &Source{
		regions: regions,
		factory: factory,
	}
}

func (s *Source) Name() string {
	return "fc"
}

func (s *Source) Discover(ctx context.Context) ([]target.Binding, error) {
	var (
		bindings []target.Binding
		errs     []error
	)

regionLoop:
	for _, region := range s.regions {
		client, err := s.factory(region)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		var nextToken string
		for {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}

			request := new(fcsdk.ListCustomDomainsRequest).SetLimit(100)
			if nextToken != "" {
				request.SetNextToken(nextToken)
			}

			response, err := client.ListCustomDomainsWithOptions(request, nil, &dara.RuntimeOptions{})
			if err != nil {
				if isUnavailableEndpoint(err) {
					errs = append(errs, target.Warningf("skip FC custom domains in %s: endpoint unavailable: %v", region, err))
					continue regionLoop
				}
				errs = append(errs, fmt.Errorf("list FC custom domains in %s: %w", region, err))
				continue regionLoop
			}
			if response == nil || response.Body == nil {
				errs = append(errs, fmt.Errorf("list FC custom domains in %s: empty response", region))
				continue regionLoop
			}

			for _, item := range response.Body.CustomDomains {
				if item == nil {
					continue
				}
				protocol := strings.ToUpper(tea.StringValue(item.Protocol))
				if !strings.Contains(protocol, "HTTPS") {
					continue
				}
				if item.CertConfig == nil || strings.TrimSpace(tea.StringValue(item.CertConfig.Certificate)) == "" {
					continue
				}

				bundle, err := certutil.BundleFromPEM(nil, tea.StringValue(item.CertConfig.Certificate), tea.StringValue(item.CertConfig.PrivateKey))
				if err != nil {
					return nil, fmt.Errorf("parse FC certificate for %s in %s: %w", tea.StringValue(item.DomainName), region, err)
				}

				domains := bundle.Domains
				if len(domains) == 0 {
					domains = []string{tea.StringValue(item.DomainName)}
				}

				bindings = append(bindings, &binding{
					client:      client,
					region:      region,
					domainName:  tea.StringValue(item.DomainName),
					protocol:    tea.StringValue(item.Protocol),
					authConfig:  item.AuthConfig,
					corsConfig:  item.CorsConfig,
					routeConfig: item.RouteConfig,
					tlsConfig:   item.TlsConfig,
					wafConfig:   item.WafConfig,
					domains:     domains,
					expiresAt:   bundle.ExpiresAt,
					fingerprint: bundle.Fingerprint,
				})
			}

			nextToken = tea.StringValue(response.Body.NextToken)
			if nextToken == "" {
				break
			}
		}
	}

	return bindings, errors.Join(errs...)
}

func (s *Source) SmokeTest(_ context.Context) error {
	if len(s.regions) == 0 {
		return nil
	}

	client, err := s.factory(s.regions[0])
	if err != nil {
		return err
	}

	_, err = client.ListCustomDomainsWithOptions(new(fcsdk.ListCustomDomainsRequest).SetLimit(1), nil, &dara.RuntimeOptions{})
	if err != nil {
		return fmt.Errorf("FC smoke test failed: %w", err)
	}
	return nil
}

type binding struct {
	client      clientAPI
	region      string
	domainName  string
	protocol    string
	authConfig  *fcsdk.AuthConfig
	corsConfig  *fcsdk.CORSConfig
	routeConfig *fcsdk.RouteConfig
	tlsConfig   *fcsdk.TLSConfig
	wafConfig   *fcsdk.WAFConfig
	domains     []string
	expiresAt   time.Time
	fingerprint string
}

func (b *binding) ResourceType() string {
	return "fc"
}

func (b *binding) DisplayName() string {
	return fmt.Sprintf("fc[%s] %s", b.region, b.domainName)
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

func (b *binding) Replace(ctx context.Context, material target.Material) error {
	if material.Bundle == nil {
		return fmt.Errorf("certificate bundle is required")
	}

	_, err := b.client.UpdateCustomDomainWithOptions(tea.String(b.domainName), b.updateRequest(material), nil, &dara.RuntimeOptions{})
	if err != nil {
		return fmt.Errorf("update FC custom domain %s: %w", b.domainName, err)
	}

	return waitFor(ctx, 2*time.Minute, 3*time.Second, func() (bool, error) {
		response, err := b.client.GetCustomDomainWithOptions(tea.String(b.domainName), nil, &dara.RuntimeOptions{})
		if err != nil {
			return false, err
		}
		if response == nil || response.Body == nil || response.Body.CertConfig == nil {
			return false, nil
		}
		current, err := certutil.BundleFromPEM(nil, tea.StringValue(response.Body.CertConfig.Certificate), tea.StringValue(response.Body.CertConfig.PrivateKey))
		if err != nil {
			return false, err
		}
		return current.Fingerprint == material.Bundle.Fingerprint, nil
	})
}

func (b *binding) updateRequest(material target.Material) *fcsdk.UpdateCustomDomainRequest {
	body := new(fcsdk.UpdateCustomDomainInput).
		SetProtocol(b.protocol).
		SetAuthConfig(b.authConfig).
		SetCorsConfig(b.corsConfig).
		SetRouteConfig(b.routeConfig).
		SetTlsConfig(b.tlsConfig).
		SetWafConfig(b.wafConfig).
		SetCertConfig(
			new(fcsdk.CertConfig).
				SetCertName(material.CertificateName).
				SetCertificate(material.Bundle.CertificatePEM).
				SetPrivateKey(material.Bundle.PrivateKeyPEM),
		)

	return new(fcsdk.UpdateCustomDomainRequest).SetBody(body)
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

func isUnavailableEndpoint(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound || strings.Contains(strings.ToLower(dnsErr.Err), "no such host") {
			return true
		}
	}
	return strings.Contains(strings.ToLower(err.Error()), "no such host")
}
