package fcinvoke

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cloudcarver/autocerts/internal/config"
)

type IssueOptions struct {
	FunctionRegion  string
	FunctionName    string
	Qualifier       string
	Domains         []string
	DNSProvider     config.DNSProviderType
	CertificateName string
	DryRun          bool
	Async           bool
}

type issuePayload struct {
	Mode            config.Mode `json:"mode"`
	Domains         []string    `json:"domains"`
	DNSProvider     string      `json:"dns_provider"`
	CertificateName string      `json:"certificateName,omitempty"`
	DryRun          bool        `json:"dryRun,omitempty"`
}

func BuildIssueInvokeArgs(opts IssueOptions) ([]string, error) {
	normalized, err := normalizeIssueOptions(opts)
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(issuePayload{
		Mode:            config.ModeIssue,
		Domains:         normalized.Domains,
		DNSProvider:     string(normalized.DNSProvider),
		CertificateName: normalized.CertificateName,
		DryRun:          normalized.DryRun,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal invoke payload: %w", err)
	}

	args := []string{
		"--region", normalized.FunctionRegion,
		"fc", "InvokeFunction",
		"--functionName", normalized.FunctionName,
		"--body", string(body),
	}
	if normalized.Async {
		args = append(args, "--header", "x-fc-invocation-type=Async")
	}
	if normalized.Qualifier != "" {
		args = append(args, "--qualifier", normalized.Qualifier)
	}
	return args, nil
}

func normalizeIssueOptions(opts IssueOptions) (IssueOptions, error) {
	out := IssueOptions{
		FunctionRegion:  strings.TrimSpace(opts.FunctionRegion),
		FunctionName:    strings.TrimSpace(opts.FunctionName),
		Qualifier:       strings.TrimSpace(opts.Qualifier),
		Domains:         normalizeList(opts.Domains),
		DNSProvider:     opts.DNSProvider,
		CertificateName: strings.TrimSpace(opts.CertificateName),
		DryRun:          opts.DryRun,
		Async:           opts.Async,
	}

	if out.FunctionRegion == "" {
		return IssueOptions{}, fmt.Errorf("fc region is required")
	}
	if out.FunctionName == "" {
		return IssueOptions{}, fmt.Errorf("fc function name is required")
	}
	if len(out.Domains) == 0 {
		return IssueOptions{}, fmt.Errorf("domains are required")
	}
	if out.DNSProvider == "" {
		return IssueOptions{}, fmt.Errorf("dns provider is required")
	}
	if _, err := config.ParseDNSProvider(string(out.DNSProvider)); err != nil {
		return IssueOptions{}, err
	}

	return out, nil
}

func SplitCSV(raw string) []string {
	return normalizeList(strings.Split(raw, ","))
}

func normalizeList(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}
