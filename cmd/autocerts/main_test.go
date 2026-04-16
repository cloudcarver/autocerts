package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRenderCLIResponseFormatsQuotedIssueJSON(t *testing.T) {
	t.Parallel()

	raw := []byte(`"{\n  \"mode\": \"issue\",\n  \"issue\": {\n    \"dryRun\": false,\n    \"reused\": true,\n    \"certificateName\": \"autocerts-example\",\n    \"dnsProvider\": \"cloudflare\",\n    \"domains\": [\"example.com\"],\n    \"uploads\": [{\"certificateId\": 42, \"certIdentifier\": \"42-global\", \"certificateName\": \"autocerts-example\", \"expiresAt\": \"2026-07-15T11:30:57Z\"}],\n    \"expiresAt\": \"2026-07-15T11:30:57Z\"\n  },\n  \"occurredAt\": \"2026-04-16T12:40:45Z\"\n}"`)

	var out bytes.Buffer
	if err := renderCLIResponse(&out, raw, false, false, "cn-shenzhen", "autocerts"); err != nil {
		t.Fatalf("renderCLIResponse returned error: %v", err)
	}

	got := out.String()
	if want := "已复用现有证书\n"; !strings.HasPrefix(got, want) {
		t.Fatalf("unexpected header: %q", got)
	}
	if !bytes.Contains(out.Bytes(), []byte("域名: example.com")) {
		t.Fatalf("unexpected body: %q", got)
	}
	if !bytes.Contains(out.Bytes(), []byte("CAS: 42-global (ID 42)")) {
		t.Fatalf("unexpected CAS line: %q", got)
	}
}

func TestRenderCLIResponseCanPrintRawJSON(t *testing.T) {
	t.Parallel()

	raw := []byte(`"{\"mode\":\"issue\"}"`)

	var out bytes.Buffer
	if err := renderCLIResponse(&out, raw, true, false, "cn-shenzhen", "autocerts"); err != nil {
		t.Fatalf("renderCLIResponse returned error: %v", err)
	}

	if got := out.String(); got != "{\"mode\":\"issue\"}\n" {
		t.Fatalf("unexpected raw output: %q", got)
	}
}

func TestRenderCLIResponsePrintsAsyncAckWithoutBody(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	if err := renderCLIResponse(&out, nil, false, true, "cn-shenzhen", "autocerts"); err != nil {
		t.Fatalf("renderCLIResponse returned error: %v", err)
	}

	if got := out.String(); got != "已提交异步调用到 cn-shenzhen/autocerts\n" {
		t.Fatalf("unexpected async output: %q", got)
	}
}

func TestDetectCommandRequiresExplicitSubcommand(t *testing.T) {
	t.Parallel()

	command, tail := detectCommand([]string{"-domains", "example.com"})
	if command != "-domains" {
		t.Fatalf("unexpected command: %q", command)
	}
	if len(tail) != 1 || tail[0] != "example.com" {
		t.Fatalf("unexpected tail: %#v", tail)
	}
}
