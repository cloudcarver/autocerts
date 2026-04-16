package renewal

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cloudcarver/autocerts/internal/certstore"
	"github.com/cloudcarver/autocerts/internal/certutil"
	"github.com/cloudcarver/autocerts/internal/config"
	"github.com/cloudcarver/autocerts/internal/target"
)

type Issuer interface {
	Issue(ctx context.Context, domains []string, provider config.DNSProviderType) (*certutil.Bundle, error)
}

type Reconciler struct {
	Sources   []target.Source
	Issuer    Issuer
	Store     certstore.Store
	Threshold time.Duration
	Now       func() time.Time
}

type Result struct {
	Discovered int      `json:"discovered"`
	Expiring   int      `json:"expiring"`
	Renewed    int      `json:"renewed"`
	Updated    int      `json:"updated"`
	DryRun     bool     `json:"dryRun"`
	Warnings   []string `json:"warnings,omitempty"`
	Actions    []Action `json:"actions,omitempty"`
}

type Action struct {
	Domains     []string               `json:"domains"`
	DNSProvider config.DNSProviderType `json:"dnsProvider,omitempty"`
	Fingerprint string                 `json:"fingerprint"`
	Resources   []string               `json:"resources"`
	Uploads     []RegionalUpload       `json:"uploads,omitempty"`
}

type RegionalUpload struct {
	Region          string `json:"region,omitempty"`
	CertIdentifier  string `json:"certIdentifier,omitempty"`
	CertificateName string `json:"certificateName,omitempty"`
}

type bindingGroup struct {
	domains     []string
	fingerprint string
	bindings    []target.Binding
}

func (r *Reconciler) Run(ctx context.Context, dryRun bool, nameFactory func([]string) string) (*Result, error) {
	if r.Now == nil {
		r.Now = time.Now
	}

	result := &Result{DryRun: dryRun}
	deadline := r.Now().UTC().Add(r.Threshold)
	groups := make(map[string]*bindingGroup)
	var errs []error

	for _, source := range r.Sources {
		bindings, err := source.Discover(ctx)
		warnings, hardErr := target.SplitWarnings(err)
		for _, warning := range warnings {
			result.addWarning(fmt.Sprintf("%s discover: %s", source.Name(), warning))
		}
		if hardErr != nil {
			errs = append(errs, fmt.Errorf("%s discover: %w", source.Name(), hardErr))
		}

		result.Discovered += len(bindings)
		for _, binding := range bindings {
			if binding.ExpiresAt().IsZero() || !binding.ExpiresAt().Before(deadline) {
				continue
			}

			result.Expiring++
			key := groupKey(binding)
			group, ok := groups[key]
			if !ok {
				group = &bindingGroup{
					domains:     certutil.NormalizeDomains(binding.Domains()),
					fingerprint: binding.Fingerprint(),
				}
				groups[key] = group
			}
			group.domains = certutil.MergeDomainSets(group.domains, binding.Domains())
			group.bindings = append(group.bindings, binding)
		}
	}

	for _, group := range groups {
		action := Action{
			Domains:     certutil.NormalizeDomains(group.domains),
			Fingerprint: group.fingerprint,
		}
		for _, binding := range group.bindings {
			action.Resources = append(action.Resources, binding.DisplayName())
		}

		if len(action.Domains) == 0 {
			errs = append(errs, fmt.Errorf("skip renewal with empty domains for resources: %s", strings.Join(action.Resources, ", ")))
			result.Actions = append(result.Actions, action)
			continue
		}

		dnsProvider, err := r.resolveDNSProvider(ctx, group)
		if err != nil {
			warnings, hardErr := target.SplitWarnings(err)
			for _, warning := range warnings {
				result.addWarning(fmt.Sprintf("resolve DNS provider for %v: %s", action.Domains, warning))
			}
			if hardErr != nil {
				errs = append(errs, fmt.Errorf("resolve DNS provider for %v: %w", action.Domains, hardErr))
			}
			result.Actions = append(result.Actions, action)
			continue
		}
		action.DNSProvider = dnsProvider

		if dryRun {
			result.Actions = append(result.Actions, action)
			continue
		}

		bundle, err := r.Issuer.Issue(ctx, action.Domains, dnsProvider)
		if err != nil {
			errs = append(errs, fmt.Errorf("issue certificate for %v: %w", action.Domains, err))
			result.Actions = append(result.Actions, action)
			continue
		}

		metadata, err := r.Store.Upload(ctx, certstore.UploadRequest{
			Name:        nameFactory(action.Domains),
			DNSProvider: dnsProvider,
			Bundle:      bundle,
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("upload certificate for %v: %w", action.Domains, err))
			result.Actions = append(result.Actions, action)
			continue
		}

		action.Uploads = append(action.Uploads, RegionalUpload{
			CertIdentifier:  metadata.CertIdentifier,
			CertificateName: metadata.CertificateName,
		})
		material := target.Material{
			Bundle:          bundle,
			CertificateID:   metadata.CertificateID,
			CertIdentifier:  metadata.CertIdentifier,
			CertificateName: metadata.CertificateName,
		}
		result.Renewed++

		for _, binding := range group.bindings {
			if err := binding.Replace(ctx, material); err != nil {
				errs = append(errs, fmt.Errorf("replace %s: %w", binding.DisplayName(), err))
				continue
			}
			result.Updated++
		}

		result.Actions = append(result.Actions, action)
	}

	return result, errors.Join(errs...)
}

func groupKey(binding target.Binding) string {
	fingerprint := strings.TrimSpace(binding.Fingerprint())
	if fingerprint != "" {
		return fingerprint
	}
	return strings.Join(certutil.SortDomains(binding.Domains()), ",")
}

func (r *Reconciler) resolveDNSProvider(ctx context.Context, group *bindingGroup) (config.DNSProviderType, error) {
	var provider config.DNSProviderType
	for _, binding := range group.bindings {
		candidate, ok := binding.(interface{ DNSProvider() config.DNSProviderType })
		if !ok {
			continue
		}

		current := candidate.DNSProvider()
		if current == "" {
			continue
		}
		if provider != "" && provider != current {
			return "", fmt.Errorf("conflicting dns providers %q and %q", provider, current)
		}
		provider = current
	}

	if provider != "" {
		return provider, nil
	}
	if strings.TrimSpace(group.fingerprint) == "" {
		return "", fmt.Errorf("certificate fingerprint is missing and no binding exposed dns provider")
	}

	metadata, err := r.Store.FindByFingerprint(ctx, "", group.fingerprint)
	if err != nil {
		if certstore.IsNotFound(err) {
			return "", target.Warningf("certificate fingerprint %q not found in CAS", group.fingerprint)
		}
		return "", err
	}
	if metadata == nil {
		return "", target.Warningf("fingerprint %q resolved to empty metadata", group.fingerprint)
	}
	if metadata.DNSProvider == "" {
		return "", target.Warningf("certificate %q is missing CAS tag %q", metadata.CertIdentifier, "dns_provider")
	}
	return metadata.DNSProvider, nil
}

func (r *Result) addWarning(warning string) {
	warning = strings.TrimSpace(warning)
	if warning == "" {
		return
	}
	for _, existing := range r.Warnings {
		if existing == warning {
			return
		}
	}
	r.Warnings = append(r.Warnings, warning)
}
