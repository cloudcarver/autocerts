package config

import (
	"testing"
)

func TestLoadFromIssueModeWithCloudflare(t *testing.T) {
	t.Parallel()

	env := map[string]string{
		"ACME_EMAIL":         "ops@example.com",
		"CLOUDFLARE_API_KEY": "token",
		"CERTIFICATE_PREFIX": "prod",
	}

	runtime, err := LoadFrom([]byte(`{"mode":"issue","domains":["example.com","*.example.com"],"dns_provider":"cloudflare"}`), func(key string) string { return env[key] })
	if err != nil {
		t.Fatalf("LoadFrom returned error: %v", err)
	}

	if runtime.Request.Mode != ModeIssue {
		t.Fatalf("unexpected mode: %s", runtime.Request.Mode)
	}
	if len(runtime.Request.Domains) != 2 {
		t.Fatalf("unexpected domains: %#v", runtime.Request.Domains)
	}
	if runtime.Request.DNSProvider != DNSProviderCloudflare {
		t.Fatalf("unexpected DNS provider: %s", runtime.Request.DNSProvider)
	}
	if runtime.Settings.CertificatePrefix != "prod" {
		t.Fatalf("unexpected certificate prefix: %s", runtime.Settings.CertificatePrefix)
	}
}

func TestLoadFromReconcileRequiresCronInterval(t *testing.T) {
	t.Parallel()

	env := map[string]string{
		"ACME_EMAIL": "ops@example.com",
		"REGIONS":    "cn-hangzhou",
	}

	_, err := LoadFrom([]byte(`{"mode":"reconcile"}`), func(key string) string { return env[key] })
	if err == nil {
		t.Fatalf("expected error when CRON_INTERVAL is missing")
	}
}

func TestLoadFromReconcileRequiresExplicitRegions(t *testing.T) {
	t.Parallel()

	env := map[string]string{
		"ACME_EMAIL":    "ops@example.com",
		"CRON_INTERVAL": "168h",
	}

	_, err := LoadFrom([]byte(`{"mode":"reconcile"}`), func(key string) string { return env[key] })
	if err == nil {
		t.Fatalf("expected missing explicit region error")
	}
}

func TestLoadFromSmokeOSSDoesNotRequireRegions(t *testing.T) {
	t.Parallel()

	env := map[string]string{
		"ACME_EMAIL": "ops@example.com",
	}

	_, err := LoadFrom([]byte(`{"mode":"smoke","components":["oss"]}`), func(key string) string { return env[key] })
	if err != nil {
		t.Fatalf("expected smoke oss to not require explicit regions, got: %v", err)
	}
}

func TestLoadFromSmokeCASDoesNotRequireRegions(t *testing.T) {
	t.Parallel()

	env := map[string]string{
		"ACME_EMAIL": "ops@example.com",
	}

	_, err := LoadFrom([]byte(`{"mode":"smoke","components":["cas"]}`), func(key string) string { return env[key] })
	if err != nil {
		t.Fatalf("expected smoke cas to not require explicit regions, got: %v", err)
	}
}

func TestLoadFromSmokeCDNDoesNotRequireRegions(t *testing.T) {
	t.Parallel()

	env := map[string]string{
		"ACME_EMAIL": "ops@example.com",
	}

	_, err := LoadFrom([]byte(`{"mode":"smoke","components":["cdn"]}`), func(key string) string { return env[key] })
	if err != nil {
		t.Fatalf("expected smoke cdn to not require explicit regions, got: %v", err)
	}
}

func TestLoadFromRejectsUnknownDNSProvider(t *testing.T) {
	t.Parallel()

	_, err := LoadFrom([]byte(`{"mode":"issue","domains":["example.com"],"dns_provider":"alidns"}`), func(key string) string {
		switch key {
		case "ACME_EMAIL":
			return "ops@example.com"
		default:
			return ""
		}
	})
	if err == nil {
		t.Fatalf("expected unsupported dns_provider error")
	}
}

func TestLoadFromIssueModeWithAliyunDoesNotRequireDedicatedDNSVars(t *testing.T) {
	t.Parallel()

	_, err := LoadFrom([]byte(`{"mode":"issue","domains":["example.com"],"dns_provider":"aliyun"}`), func(key string) string {
		switch key {
		case "ACME_EMAIL":
			return "ops@example.com"
		default:
			return ""
		}
	})
	if err != nil {
		t.Fatalf("expected aliyun issue to rely on default auth, got: %v", err)
	}
}

func TestLoadFromRequiresMode(t *testing.T) {
	t.Parallel()

	_, err := LoadFrom([]byte(`{}`), func(string) string { return "" })
	if err == nil {
		t.Fatalf("expected missing mode error")
	}
}

func TestLoadFromIssueDoesNotRequireRegions(t *testing.T) {
	t.Parallel()

	_, err := LoadFrom([]byte(`{"mode":"issue","domains":["example.com"],"dns_provider":"cloudflare"}`), func(key string) string {
		switch key {
		case "ACME_EMAIL":
			return "ops@example.com"
		case "CLOUDFLARE_API_KEY":
			return "token"
		default:
			return ""
		}
	})
	if err != nil {
		t.Fatalf("expected issue without regions to be valid, got: %v", err)
	}
}
