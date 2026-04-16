package acme

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"strings"

	"github.com/cloudcarver/autocerts/internal/certutil"
	"github.com/cloudcarver/autocerts/internal/config"
	aliyunauth "github.com/cloudcarver/autocerts/internal/platform/aliyun/auth"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/alidns"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
)

type Issuer interface {
	Issue(ctx context.Context, domains []string, provider config.DNSProviderType) (*certutil.Bundle, error)
	SmokeTest(ctx context.Context) error
}

type LegoIssuer struct {
	settings config.Settings
}

func NewLegoIssuer(settings config.Settings) *LegoIssuer {
	return &LegoIssuer{settings: settings}
}

func (i *LegoIssuer) Issue(_ context.Context, domains []string, provider config.DNSProviderType) (*certutil.Bundle, error) {
	normalizedDomains := certutil.NormalizeDomains(domains)
	if len(normalizedDomains) == 0 {
		return nil, fmt.Errorf("at least one domain is required")
	}

	accountKey, err := i.accountKey()
	if err != nil {
		return nil, err
	}

	user := &legoUser{
		email: i.settings.ACMEEmail,
		key:   accountKey,
	}

	legoConfig := lego.NewConfig(user)
	legoConfig.CADirURL = i.settings.ACMEDirectoryURL
	legoConfig.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(legoConfig)
	if err != nil {
		return nil, fmt.Errorf("create ACME client: %w", err)
	}

	dnsProvider, err := i.challengeProvider(provider)
	if err != nil {
		return nil, err
	}
	if err := client.Challenge.SetDNS01Provider(dnsProvider); err != nil {
		return nil, fmt.Errorf("configure DNS-01 provider: %w", err)
	}

	registrationData, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "already exists") {
			return nil, fmt.Errorf("register ACME account: %w", err)
		}
		registrationData, err = client.Registration.ResolveAccountByKey()
		if err != nil {
			return nil, fmt.Errorf("resolve existing ACME account: %w", err)
		}
	}
	user.registration = registrationData

	resource, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: normalizedDomains,
		Bundle:  true,
	})
	if err != nil {
		return nil, fmt.Errorf("obtain certificate: %w", err)
	}

	certificatePEM := strings.TrimSpace(string(resource.Certificate))
	if issuer := strings.TrimSpace(string(resource.IssuerCertificate)); issuer != "" {
		certificatePEM = certificatePEM + "\n" + issuer + "\n"
	} else {
		certificatePEM += "\n"
	}

	return certutil.BundleFromPEM(normalizedDomains, certificatePEM, string(resource.PrivateKey))
}

func (i *LegoIssuer) SmokeTest(_ context.Context) error {
	providers := i.settings.Challenge.ConfiguredProviders()
	if len(providers) == 0 {
		providers = []config.DNSProviderType{config.DNSProviderAliyun}
	}

	var errs []error
	for _, provider := range providers {
		if _, err := i.challengeProvider(provider); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (i *LegoIssuer) challengeProvider(provider config.DNSProviderType) (challenge.Provider, error) {
	switch provider {
	case config.DNSProviderCloudflare:
		cfg := cloudflare.NewDefaultConfig()
		if email := strings.TrimSpace(i.settings.Challenge.CloudflareEmail); email != "" {
			cfg.AuthEmail = email
			cfg.AuthKey = i.settings.Challenge.CloudflareAPIKey
		} else {
			cfg.AuthToken = i.settings.Challenge.CloudflareAPIKey
			cfg.ZoneToken = i.settings.Challenge.CloudflareAPIKey
		}
		return cloudflare.NewDNSProviderConfig(cfg)
	case config.DNSProviderAliyun:
		cfg := alidns.NewDefaultConfig()
		actual, err := i.aliyunDNSCredential()
		if err != nil {
			return nil, err
		}
		cfg.APIKey = actual.AccessKeyID
		cfg.SecretKey = actual.AccessKeySecret
		cfg.SecurityToken = actual.SecurityToken
		return alidns.NewDNSProviderConfig(cfg)
	default:
		return nil, fmt.Errorf("unsupported DNS provider %q", provider)
	}
}

func (i *LegoIssuer) aliyunDNSCredential() (*aliyunauth.CredentialSnapshot, error) {
	provider, err := aliyunauth.NewProvider()
	if err != nil {
		return nil, fmt.Errorf("resolve aliyun default credential for DNS provider: %w", err)
	}

	actual, err := provider.CredentialSnapshot()
	if err != nil {
		return nil, fmt.Errorf("resolve aliyun default credential for DNS provider: %w", err)
	}
	if strings.TrimSpace(actual.AccessKeyID) == "" || strings.TrimSpace(actual.AccessKeySecret) == "" {
		return nil, fmt.Errorf("resolve aliyun default credential for DNS provider: access key credential is required")
	}
	return actual, nil
}

func (i *LegoIssuer) accountKey() (crypto.PrivateKey, error) {
	if strings.TrimSpace(i.settings.ACMEAccountPrivateKeyPEM) != "" {
		key, err := certcrypto.ParsePEMPrivateKey([]byte(normalizeInlinePEM(i.settings.ACMEAccountPrivateKeyPEM)))
		if err != nil {
			return nil, fmt.Errorf("parse ACME account private key: %w", err)
		}
		return key, nil
	}

	key, err := certcrypto.GeneratePrivateKey(certcrypto.EC256)
	if err != nil {
		return nil, fmt.Errorf("generate ACME account private key: %w", err)
	}
	return key, nil
}

type legoUser struct {
	email        string
	registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *legoUser) GetEmail() string {
	return u.email
}

func (u *legoUser) GetRegistration() *registration.Resource {
	return u.registration
}

func (u *legoUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func normalizeInlinePEM(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}

	normalized := strings.ReplaceAll(trimmed, `\r\n`, "\n")
	normalized = strings.ReplaceAll(normalized, `\n`, "\n")
	normalized = strings.ReplaceAll(normalized, `\r`, "\n")
	normalized = strings.ReplaceAll(normalized, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	return normalized
}
