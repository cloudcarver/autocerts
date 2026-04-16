package fcinvoke

import (
	"encoding/json"
	"testing"

	"github.com/cloudcarver/autocerts/internal/config"
)

func TestBuildIssueInvokeArgs(t *testing.T) {
	t.Parallel()

	args, err := BuildIssueInvokeArgs(IssueOptions{
		FunctionRegion:  "cn-shenzhen",
		FunctionName:    "autocerts",
		Qualifier:       "LATEST",
		Domains:         []string{"example.com", "*.example.com"},
		DNSProvider:     config.DNSProviderCloudflare,
		CertificateName: "autocerts-example",
		DryRun:          true,
		Async:           true,
	})
	if err != nil {
		t.Fatalf("BuildIssueInvokeArgs returned error: %v", err)
	}

	if len(args) != 12 {
		t.Fatalf("unexpected args length: %#v", args)
	}
	if args[0] != "--region" || args[1] != "cn-shenzhen" {
		t.Fatalf("unexpected region args: %#v", args)
	}
	if args[2] != "fc" || args[3] != "InvokeFunction" {
		t.Fatalf("unexpected invoke args: %#v", args)
	}
	if args[4] != "--functionName" || args[5] != "autocerts" {
		t.Fatalf("unexpected function args: %#v", args)
	}
	if args[6] != "--body" {
		t.Fatalf("unexpected body arg: %#v", args)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(args[7]), &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload["mode"] != "issue" {
		t.Fatalf("unexpected mode: %#v", payload["mode"])
	}
	if payload["dns_provider"] != "cloudflare" {
		t.Fatalf("unexpected dns provider: %#v", payload["dns_provider"])
	}
	if payload["certificateName"] != "autocerts-example" {
		t.Fatalf("unexpected certificateName: %#v", payload["certificateName"])
	}
	if payload["dryRun"] != true {
		t.Fatalf("unexpected dryRun: %#v", payload["dryRun"])
	}
	if args[8] != "--header" || args[9] != "x-fc-invocation-type=Async" {
		t.Fatalf("unexpected async header args: %#v", args)
	}
	if args[10] != "--qualifier" || args[11] != "LATEST" {
		t.Fatalf("unexpected qualifier args: %#v", args)
	}
}

func TestBuildIssueInvokeArgsDoesNotRequireRegions(t *testing.T) {
	t.Parallel()

	_, err := BuildIssueInvokeArgs(IssueOptions{
		FunctionRegion: "cn-shenzhen",
		FunctionName:   "autocerts",
		Domains:        []string{"example.com"},
		DNSProvider:    config.DNSProviderCloudflare,
	})
	if err != nil {
		t.Fatalf("expected issue args without regions to be valid, got: %v", err)
	}
}

func TestSplitCSV(t *testing.T) {
	t.Parallel()

	got := SplitCSV(" cn-shenzhen, cn-hangzhou, cn-shenzhen ,, ")
	if len(got) != 2 || got[0] != "cn-shenzhen" || got[1] != "cn-hangzhou" {
		t.Fatalf("unexpected split result: %#v", got)
	}
}
