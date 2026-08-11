package alb

import (
	"context"
	"errors"
	"strings"
	"testing"

	albsdk "github.com/alibabacloud-go/alb-20200616/v2/client"

	"github.com/cloudcarver/autocerts/internal/target"
)

func TestReplaceDelegatesServiceManagedDefaultListener(t *testing.T) {
	t.Parallel()

	b := &binding{
		client: &clientStub{
			updateErr: errors.New("OperationDenied.ServiceManagedResource: The operation is not allowed because the current resource is managed resource"),
		},
		region:        "cn-shenzhen",
		listenerID:    "lsn-managed",
		loadBalancer:  "alb-managed",
		currentCertID: "old-cert",
		isDefault:     true,
	}

	err := b.Replace(context.Background(), target.Material{CertIdentifier: "new-cert"})
	warnings, hardErr := target.SplitWarnings(err)
	if hardErr != nil {
		t.Fatalf("expected a warning-only result, got %v", hardErr)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "managed by another service") {
		t.Fatalf("unexpected warnings: %#v", warnings)
	}
}

func TestReplaceKeepsOrdinaryALBFailureHard(t *testing.T) {
	t.Parallel()

	b := &binding{
		client:        &clientStub{updateErr: errors.New("ordinary failure")},
		currentCertID: "old-cert",
		isDefault:     true,
	}

	err := b.Replace(context.Background(), target.Material{CertIdentifier: "new-cert"})
	warnings, hardErr := target.SplitWarnings(err)
	if len(warnings) != 0 || hardErr == nil || !strings.Contains(hardErr.Error(), "ordinary failure") {
		t.Fatalf("expected a hard ALB error, warnings=%#v hard=%v", warnings, hardErr)
	}
}

type clientStub struct {
	updateErr error
}

func (c *clientStub) ListListeners(*albsdk.ListListenersRequest) (*albsdk.ListListenersResponse, error) {
	return nil, nil
}

func (c *clientStub) ListListenerCertificates(*albsdk.ListListenerCertificatesRequest) (*albsdk.ListListenerCertificatesResponse, error) {
	return nil, nil
}

func (c *clientStub) UpdateListenerAttribute(*albsdk.UpdateListenerAttributeRequest) (*albsdk.UpdateListenerAttributeResponse, error) {
	return nil, c.updateErr
}

func (c *clientStub) AssociateAdditionalCertificatesWithListener(*albsdk.AssociateAdditionalCertificatesWithListenerRequest) (*albsdk.AssociateAdditionalCertificatesWithListenerResponse, error) {
	return nil, nil
}

func (c *clientStub) DissociateAdditionalCertificatesFromListener(*albsdk.DissociateAdditionalCertificatesFromListenerRequest) (*albsdk.DissociateAdditionalCertificatesFromListenerResponse, error) {
	return nil, nil
}
