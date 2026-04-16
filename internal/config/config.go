package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

type Mode string

const (
	ModeIssue     Mode = "issue"
	ModeReconcile Mode = "reconcile"
	ModeSmoke     Mode = "smoke"
)

type DNSProviderType string

const (
	DNSProviderCloudflare DNSProviderType = "cloudflare"
	DNSProviderAliyun     DNSProviderType = "aliyun"
)

type Request struct {
	Mode            Mode     `json:"mode"`
	Domains         []string `json:"domains,omitempty"`
	Regions         []string `json:"regions,omitempty"`
	CertificateName string   `json:"certificateName,omitempty"`
	DNSProvider     DNSProviderType
	DryRun          bool     `json:"dryRun,omitempty"`
	Components      []string `json:"components,omitempty"`
}

type ChallengeConfig struct {
	CloudflareAPIKey string
	CloudflareEmail  string
}

type Settings struct {
	ACMEEmail                string
	ACMEDirectoryURL         string
	ACMEAccountPrivateKeyPEM string
	Challenge                ChallengeConfig
	CRONInterval             time.Duration
	CASResourceGroupID       string
	CertificatePrefix        string
	Regions                  []string
	AccountID                string
}

type Runtime struct {
	Request  Request
	Settings Settings
}

func Load(event []byte) (*Runtime, error) {
	return LoadFrom(event, os.Getenv)
}

func LoadFrom(event []byte, lookup func(string) string) (*Runtime, error) {
	req, err := parseRequest(event)
	if err != nil {
		return nil, err
	}

	settings, err := loadSettings(lookup)
	if err != nil {
		return nil, err
	}

	runtime := &Runtime{
		Request:  req,
		Settings: settings,
	}

	if err := runtime.validate(); err != nil {
		return nil, err
	}

	return runtime, nil
}

func parseRequest(event []byte) (Request, error) {
	if len(bytes.TrimSpace(event)) == 0 {
		return Request{}, nil
	}

	type rawRequest struct {
		Mode            Mode     `json:"mode"`
		Domains         []string `json:"domains,omitempty"`
		Regions         []string `json:"regions,omitempty"`
		CertificateName string   `json:"certificateName,omitempty"`
		DNSProvider     string   `json:"dns_provider,omitempty"`
		DNSProviderAlt  string   `json:"dnsProvider,omitempty"`
		DryRun          bool     `json:"dryRun,omitempty"`
		Components      []string `json:"components,omitempty"`
	}

	var raw rawRequest
	if err := json.Unmarshal(event, &raw); err != nil {
		return Request{}, fmt.Errorf("parse request event: %w", err)
	}

	dnsProvider, err := ParseDNSProvider(firstNonEmpty(raw.DNSProvider, raw.DNSProviderAlt))
	if err != nil {
		return Request{}, err
	}

	req := Request{
		Mode:            raw.Mode,
		Domains:         normalizeStrings(raw.Domains),
		Regions:         normalizeStrings(raw.Regions),
		CertificateName: strings.TrimSpace(raw.CertificateName),
		DNSProvider:     dnsProvider,
		DryRun:          raw.DryRun,
		Components:      normalizeStrings(raw.Components),
	}
	req.Domains = normalizeStrings(req.Domains)
	req.Components = normalizeStrings(req.Components)
	return req, nil
}

func loadSettings(lookup func(string) string) (Settings, error) {
	settings := Settings{
		ACMEEmail:                strings.TrimSpace(lookup("ACME_EMAIL")),
		ACMEDirectoryURL:         firstNonEmpty(strings.TrimSpace(lookup("LETSENCRYPT_DIRECTORY_URL")), "https://acme-v02.api.letsencrypt.org/directory"),
		ACMEAccountPrivateKeyPEM: lookup("ACME_ACCOUNT_PRIVATE_KEY_PEM"),
		CASResourceGroupID:       strings.TrimSpace(lookup("ALIYUN_SSL_RESOURCE_GROUP_ID")),
		CertificatePrefix:        firstNonEmpty(strings.TrimSpace(lookup("CERTIFICATE_PREFIX")), "autocerts"),
		Regions:                  parseRegions(lookup),
		AccountID:                firstNonEmpty(strings.TrimSpace(lookup("FC_ACCOUNT_ID")), strings.TrimSpace(lookup("ALIBABA_CLOUD_ACCOUNT_ID"))),
	}

	if raw := strings.TrimSpace(lookup("CRON_INTERVAL")); raw != "" {
		interval, err := time.ParseDuration(raw)
		if err != nil {
			return Settings{}, fmt.Errorf("parse CRON_INTERVAL: %w", err)
		}
		settings.CRONInterval = interval
	}

	challenge, err := loadChallengeConfig(lookup)
	if err != nil {
		return Settings{}, err
	}
	settings.Challenge = challenge

	return settings, nil
}

func loadChallengeConfig(lookup func(string) string) (ChallengeConfig, error) {
	return ChallengeConfig{
		CloudflareAPIKey: strings.TrimSpace(lookup("CLOUDFLARE_API_KEY")),
		CloudflareEmail:  strings.TrimSpace(lookup("CLOUDFLARE_EMAIL")),
	}, nil
}

func (r *Runtime) validate() error {
	if r.Request.Mode == "" {
		return fmt.Errorf("request mode is required")
	}

	switch r.Request.Mode {
	case ModeIssue:
		if len(r.Request.Domains) == 0 {
			return fmt.Errorf("issue mode requires domains")
		}
		return r.validateIssueInputs()
	case ModeReconcile:
		if r.Settings.CRONInterval <= 0 {
			return fmt.Errorf("reconcile mode requires CRON_INTERVAL")
		}
		if err := r.validateReconcileRegions(); err != nil {
			return err
		}
		if strings.TrimSpace(r.Settings.ACMEEmail) == "" {
			return fmt.Errorf("ACME_EMAIL is required")
		}
		return nil
	case ModeSmoke:
		return r.validateSmokeInputs()
	default:
		return fmt.Errorf("unsupported mode %q", r.Request.Mode)
	}
}

func (r *Runtime) validateIssueInputs() error {
	if strings.TrimSpace(r.Settings.ACMEEmail) == "" {
		return fmt.Errorf("ACME_EMAIL is required")
	}
	if r.Request.DNSProvider == "" {
		return fmt.Errorf("issue mode requires dns_provider")
	}
	if r.Request.DNSProvider == DNSProviderCloudflare && !r.Settings.Challenge.HasProvider(DNSProviderCloudflare) {
		return fmt.Errorf("DNS provider %q is not configured", r.Request.DNSProvider)
	}
	return nil
}

func (r *Runtime) validateReconcileRegions() error {
	if len(r.Settings.Regions) == 0 {
		return fmt.Errorf("reconcile mode requires REGIONS")
	}
	return nil
}

func (r *Runtime) validateSmokeInputs() error {
	components := r.Request.Components
	if len(components) == 0 {
		components = []string{"dns", "cas", "alb", "cdn", "oss", "fc"}
	}

	for _, component := range components {
		switch component {
		case "dns":
		case "cas":
		case "alb":
			if len(r.Settings.Regions) == 0 {
				return fmt.Errorf("smoke mode component alb requires REGIONS")
			}
		case "cdn":
		case "oss":
		case "fc":
			if len(r.Settings.Regions) == 0 {
				return fmt.Errorf("smoke mode component fc requires REGIONS")
			}
		default:
		}
	}
	return nil
}

func ParseDNSProvider(raw string) (DNSProviderType, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", nil
	case string(DNSProviderCloudflare):
		return DNSProviderCloudflare, nil
	case string(DNSProviderAliyun):
		return DNSProviderAliyun, nil
	default:
		return "", fmt.Errorf("unsupported dns_provider %q", raw)
	}
}

func (c ChallengeConfig) HasAnyProvider() bool {
	return c.HasProvider(DNSProviderCloudflare)
}

func (c ChallengeConfig) HasProvider(provider DNSProviderType) bool {
	switch provider {
	case DNSProviderCloudflare:
		return strings.TrimSpace(c.CloudflareAPIKey) != ""
	default:
		return false
	}
}

func (c ChallengeConfig) ConfiguredProviders() []DNSProviderType {
	var providers []DNSProviderType
	if c.HasProvider(DNSProviderCloudflare) {
		providers = append(providers, DNSProviderCloudflare)
	}
	return providers
}

func parseRegions(lookup func(string) string) []string {
	return splitCSV(lookup("REGIONS"))
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	return normalizeStrings(parts)
}

func normalizeStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return dedupePreserveOrder(out)
}

func dedupePreserveOrder(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		key := strings.ToLower(strings.TrimSpace(value))
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, strings.TrimSpace(value))
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
