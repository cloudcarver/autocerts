package acme

import (
	"strings"
	"testing"

	"github.com/cloudcarver/autocerts/internal/config"
	"github.com/go-acme/lego/v4/certcrypto"
)

func TestAccountKeyAcceptsMultilinePEM(t *testing.T) {
	t.Parallel()

	pemKey := mustGeneratePEMKey(t)
	issuer := NewLegoIssuer(config.Settings{
		ACMEAccountPrivateKeyPEM: pemKey,
	})

	key, err := issuer.accountKey()
	if err != nil {
		t.Fatalf("accountKey returned error: %v", err)
	}
	if key == nil {
		t.Fatalf("expected parsed key")
	}
}

func TestAccountKeyAcceptsEscapedPEM(t *testing.T) {
	t.Parallel()

	pemKey := mustGeneratePEMKey(t)
	inline := strings.ReplaceAll(strings.TrimSpace(pemKey), "\n", `\n`)
	issuer := NewLegoIssuer(config.Settings{
		ACMEAccountPrivateKeyPEM: inline,
	})

	key, err := issuer.accountKey()
	if err != nil {
		t.Fatalf("accountKey returned error: %v", err)
	}
	if key == nil {
		t.Fatalf("expected parsed key")
	}
}

func TestNormalizeInlinePEM(t *testing.T) {
	t.Parallel()

	got := normalizeInlinePEM("line1\\nline2\\r\\nline3")
	want := "line1\nline2\nline3"
	if got != want {
		t.Fatalf("normalizeInlinePEM() = %q, want %q", got, want)
	}
}

func mustGeneratePEMKey(t *testing.T) string {
	t.Helper()

	key, err := certcrypto.GeneratePrivateKey(certcrypto.EC256)
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	return string(certcrypto.PEMEncode(key))
}
