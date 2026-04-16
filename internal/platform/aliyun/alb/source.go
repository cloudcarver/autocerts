package alb

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	albsdk "github.com/alibabacloud-go/alb-20200616/v2/client"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/utils"
	"github.com/alibabacloud-go/tea/tea"
	credential "github.com/aliyun/credentials-go/credentials"

	"github.com/cloudcarver/autocerts/internal/certstore"
	"github.com/cloudcarver/autocerts/internal/config"
	"github.com/cloudcarver/autocerts/internal/target"
)

type catalog interface {
	FindByIdentifier(ctx context.Context, region, identifier string) (*certstore.Metadata, error)
}

type clientAPI interface {
	ListListeners(request *albsdk.ListListenersRequest) (*albsdk.ListListenersResponse, error)
	ListListenerCertificates(request *albsdk.ListListenerCertificatesRequest) (*albsdk.ListListenerCertificatesResponse, error)
	UpdateListenerAttribute(request *albsdk.UpdateListenerAttributeRequest) (*albsdk.UpdateListenerAttributeResponse, error)
	AssociateAdditionalCertificatesWithListener(request *albsdk.AssociateAdditionalCertificatesWithListenerRequest) (*albsdk.AssociateAdditionalCertificatesWithListenerResponse, error)
	DissociateAdditionalCertificatesFromListener(request *albsdk.DissociateAdditionalCertificatesFromListenerRequest) (*albsdk.DissociateAdditionalCertificatesFromListenerResponse, error)
}

type clientFactory func(region string) (clientAPI, error)

type Source struct {
	regions []string
	catalog catalog
	factory clientFactory
}

func NewSource(regions []string, credentialClient credential.Credential, certCatalog catalog) *Source {
	var (
		mu      sync.Mutex
		clients = make(map[string]clientAPI)
	)

	return &Source{
		regions: regions,
		catalog: certCatalog,
		factory: func(region string) (clientAPI, error) {
			mu.Lock()
			defer mu.Unlock()
			if client, ok := clients[region]; ok {
				return client, nil
			}

			cfg := new(openapi.Config).SetRegionId(region).SetCredential(credentialClient)
			client, err := albsdk.NewClient(cfg)
			if err != nil {
				return nil, fmt.Errorf("create ALB client for %s: %w", region, err)
			}
			clients[region] = client
			return client, nil
		},
	}
}

func NewSourceWithFactory(regions []string, certCatalog catalog, factory clientFactory) *Source {
	return &Source{
		regions: regions,
		catalog: certCatalog,
		factory: factory,
	}
}

func (s *Source) Name() string {
	return "alb"
}

func (s *Source) Discover(ctx context.Context) ([]target.Binding, error) {
	var (
		bindings []target.Binding
		errs     []error
	)

	for _, region := range s.regions {
		client, err := s.factory(region)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		for _, protocol := range []string{"HTTPS", "QUIC"} {
			listeners, err := listListenersByProtocol(ctx, client, protocol)
			if err != nil {
				errs = append(errs, fmt.Errorf("list %s listeners in %s: %w", protocol, region, err))
				continue
			}

			for _, listener := range listeners {
				certs, err := listListenerCertificates(ctx, client, tea.StringValue(listener.ListenerId))
				if err != nil {
					errs = append(errs, fmt.Errorf("list listener certificates in %s for %s: %w", region, tea.StringValue(listener.ListenerId), err))
					continue
				}

				for _, cert := range certs {
					identifier := tea.StringValue(cert.CertificateId)
					metadata, err := s.catalog.FindByIdentifier(ctx, region, identifier)
					if err != nil {
						if certstore.IsNotFound(err) {
							errs = append(errs, target.Warningf("resolve ALB certificate %s in %s: %v", identifier, region, err))
							continue
						}
						errs = append(errs, fmt.Errorf("resolve ALB certificate %s in %s: %w", identifier, region, err))
						continue
					}

					bindings = append(bindings, &binding{
						client:        client,
						region:        region,
						listenerID:    tea.StringValue(listener.ListenerId),
						loadBalancer:  tea.StringValue(listener.LoadBalancerId),
						currentCertID: identifier,
						isDefault:     tea.BoolValue(cert.IsDefault),
						dnsProvider:   metadata.DNSProvider,
						domains:       metadata.Domains,
						expiresAt:     metadata.ExpiresAt,
						fingerprint:   metadata.Fingerprint,
					})
				}
			}
		}
	}

	return bindings, errors.Join(errs...)
}

func (s *Source) SmokeTest(ctx context.Context) error {
	for _, region := range s.regions {
		client, err := s.factory(region)
		if err != nil {
			return err
		}
		_, err = listListenersByProtocol(ctx, client, "HTTPS")
		if err != nil {
			return err
		}
		break
	}
	return nil
}

type binding struct {
	client        clientAPI
	region        string
	listenerID    string
	loadBalancer  string
	currentCertID string
	isDefault     bool
	dnsProvider   config.DNSProviderType
	domains       []string
	expiresAt     time.Time
	fingerprint   string
}

func (b *binding) ResourceType() string {
	return "alb"
}

func (b *binding) DisplayName() string {
	role := "additional"
	if b.isDefault {
		role = "default"
	}
	return fmt.Sprintf("alb[%s] %s/%s (%s)", b.region, b.loadBalancer, b.listenerID, role)
}

func (b *binding) Region() string {
	return b.region
}

func (b *binding) Domains() []string {
	return append([]string(nil), b.domains...)
}

func (b *binding) ExpiresAt() time.Time {
	return b.expiresAt
}

func (b *binding) Fingerprint() string {
	return b.fingerprint
}

func (b *binding) DNSProvider() config.DNSProviderType {
	return b.dnsProvider
}

func (b *binding) Replace(ctx context.Context, material target.Material) error {
	if material.CertIdentifier == "" {
		return fmt.Errorf("CAS cert identifier is required")
	}
	if material.CertIdentifier == b.currentCertID {
		return nil
	}

	if b.isDefault {
		_, err := b.client.UpdateListenerAttribute(
			new(albsdk.UpdateListenerAttributeRequest).
				SetListenerId(b.listenerID).
				SetClientToken(clientToken()).
				SetCertificates([]*albsdk.UpdateListenerAttributeRequestCertificates{
					new(albsdk.UpdateListenerAttributeRequestCertificates).SetCertificateId(material.CertIdentifier),
				}),
		)
		if err != nil {
			return fmt.Errorf("update default listener certificate: %w", err)
		}

		return b.waitForCertificate(ctx, material.CertIdentifier, true)
	}

	_, err := b.client.AssociateAdditionalCertificatesWithListener(
		new(albsdk.AssociateAdditionalCertificatesWithListenerRequest).
			SetListenerId(b.listenerID).
			SetClientToken(clientToken()).
			SetCertificates([]*albsdk.AssociateAdditionalCertificatesWithListenerRequestCertificates{
				new(albsdk.AssociateAdditionalCertificatesWithListenerRequestCertificates).SetCertificateId(material.CertIdentifier),
			}),
	)
	if err != nil {
		return fmt.Errorf("associate additional certificate: %w", err)
	}

	if err := b.waitForCertificate(ctx, material.CertIdentifier, false); err != nil {
		return err
	}

	_, err = b.client.DissociateAdditionalCertificatesFromListener(
		new(albsdk.DissociateAdditionalCertificatesFromListenerRequest).
			SetListenerId(b.listenerID).
			SetClientToken(clientToken()).
			SetCertificates([]*albsdk.DissociateAdditionalCertificatesFromListenerRequestCertificates{
				new(albsdk.DissociateAdditionalCertificatesFromListenerRequestCertificates).SetCertificateId(b.currentCertID),
			}),
	)
	if err != nil {
		return fmt.Errorf("dissociate old additional certificate: %w", err)
	}

	return waitFor(ctx, 2*time.Minute, 3*time.Second, func() (bool, error) {
		certs, err := listListenerCertificates(ctx, b.client, b.listenerID)
		if err != nil {
			return false, err
		}
		for _, cert := range certs {
			if tea.StringValue(cert.CertificateId) == b.currentCertID {
				return false, nil
			}
		}
		return true, nil
	})
}

func (b *binding) waitForCertificate(ctx context.Context, identifier string, isDefault bool) error {
	return waitFor(ctx, 2*time.Minute, 3*time.Second, func() (bool, error) {
		certs, err := listListenerCertificates(ctx, b.client, b.listenerID)
		if err != nil {
			return false, err
		}
		for _, cert := range certs {
			if tea.StringValue(cert.CertificateId) != identifier {
				continue
			}
			if tea.BoolValue(cert.IsDefault) != isDefault {
				continue
			}
			status := strings.ToLower(tea.StringValue(cert.Status))
			return status == "" || status == "associated", nil
		}
		return false, nil
	})
}

func listListenersByProtocol(ctx context.Context, client clientAPI, protocol string) ([]*albsdk.ListListenersResponseBodyListeners, error) {
	var listeners []*albsdk.ListListenersResponseBodyListeners
	var nextToken string

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		request := new(albsdk.ListListenersRequest).SetListenerProtocol(protocol).SetMaxResults(100)
		if nextToken != "" {
			request.SetNextToken(nextToken)
		}

		response, err := client.ListListeners(request)
		if err != nil {
			return nil, err
		}

		listeners = append(listeners, response.Body.Listeners...)
		nextToken = tea.StringValue(response.Body.NextToken)
		if nextToken == "" {
			return listeners, nil
		}
	}
}

func listListenerCertificates(ctx context.Context, client clientAPI, listenerID string) ([]*albsdk.ListListenerCertificatesResponseBodyCertificates, error) {
	var certificates []*albsdk.ListListenerCertificatesResponseBodyCertificates
	var nextToken string

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		request := new(albsdk.ListListenerCertificatesRequest).
			SetListenerId(listenerID).
			SetCertificateType("Server").
			SetMaxResults(100)
		if nextToken != "" {
			request.SetNextToken(nextToken)
		}

		response, err := client.ListListenerCertificates(request)
		if err != nil {
			return nil, err
		}

		certificates = append(certificates, response.Body.Certificates...)
		nextToken = tea.StringValue(response.Body.NextToken)
		if nextToken == "" {
			return certificates, nil
		}
	}
}

func waitFor(ctx context.Context, timeout, interval time.Duration, check func() (bool, error)) error {
	deadline := time.Now().Add(timeout)
	for {
		done, err := check()
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s", timeout)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}

func clientToken() string {
	return fmt.Sprintf("autocerts-%d", time.Now().UnixNano())
}
