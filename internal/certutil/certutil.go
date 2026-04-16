package certutil

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Bundle struct {
	Domains        []string
	CertificatePEM string
	PrivateKeyPEM  string
	ExpiresAt      time.Time
	Fingerprint    string
}

func ParseLeafCertificatePEM(certificatePEM string) (*x509.Certificate, error) {
	remaining := []byte(certificatePEM)
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		remaining = rest
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		return cert, nil
	}

	return nil, fmt.Errorf("no PEM certificate found")
}

func DomainsFromCertificate(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}

	values := make([]string, 0, 1+len(cert.DNSNames))
	if strings.TrimSpace(cert.Subject.CommonName) != "" {
		values = append(values, cert.Subject.CommonName)
	}
	values = append(values, cert.DNSNames...)
	return NormalizeDomains(values)
}

func NormalizeDomains(domains []string) []string {
	if len(domains) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(domains))
	out := make([]string, 0, len(domains))
	for _, domain := range domains {
		normalized := strings.ToLower(strings.TrimSpace(domain))
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

func MergeDomainSets(domains ...[]string) []string {
	var merged []string
	for _, items := range domains {
		merged = append(merged, items...)
	}
	return NormalizeDomains(merged)
}

func FingerprintSHA256(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func BundleFromPEM(domains []string, certificatePEM, privateKeyPEM string) (*Bundle, error) {
	leaf, err := ParseLeafCertificatePEM(certificatePEM)
	if err != nil {
		return nil, err
	}

	normalized := NormalizeDomains(domains)
	if len(normalized) == 0 {
		normalized = DomainsFromCertificate(leaf)
	}

	return &Bundle{
		Domains:        normalized,
		CertificatePEM: certificatePEM,
		PrivateKeyPEM:  privateKeyPEM,
		ExpiresAt:      leaf.NotAfter.UTC(),
		Fingerprint:    FingerprintSHA256(leaf),
	}, nil
}

func MakeCertificateName(prefix string, domains []string, now time.Time) string {
	base := "certificate"
	if len(domains) > 0 {
		base = domains[0]
	}

	sanitized := sanitizeNameComponent(base)
	name := fmt.Sprintf("%s-%s-%s", sanitizeNameComponent(prefix), sanitized, now.UTC().Format("20060102150405"))
	if len(name) <= 64 {
		return name
	}
	return name[:64]
}

func SortDomains(domains []string) []string {
	out := append([]string(nil), NormalizeDomains(domains)...)
	sort.Strings(out)
	return out
}

func ParseAlibabaTime(raw int64) time.Time {
	if raw <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(raw).UTC()
}

func ParseOSSRFC1123(raw string) (time.Time, error) {
	if strings.TrimSpace(raw) == "" {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC1123, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse RFC1123 time %q: %w", raw, err)
	}
	return parsed.UTC(), nil
}

var invalidNameChars = regexp.MustCompile(`[^a-z0-9-]+`)

func sanitizeNameComponent(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "*", "wildcard")
	value = strings.ReplaceAll(value, ".", "-")
	value = invalidNameChars.ReplaceAllString(value, "-")
	value = strings.Trim(value, "-")
	if value == "" {
		return "default"
	}
	return value
}
