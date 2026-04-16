package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aliyun/fc-runtime-go-sdk/fc"
	"github.com/cloudcarver/autocerts/internal/acme"
	"github.com/cloudcarver/autocerts/internal/app"
	"github.com/cloudcarver/autocerts/internal/certstore"
	"github.com/cloudcarver/autocerts/internal/config"
	aliyunalb "github.com/cloudcarver/autocerts/internal/platform/aliyun/alb"
	aliyunauth "github.com/cloudcarver/autocerts/internal/platform/aliyun/auth"
	aliyuncas "github.com/cloudcarver/autocerts/internal/platform/aliyun/cas"
	aliyuncdn "github.com/cloudcarver/autocerts/internal/platform/aliyun/cdn"
	aliyunfc "github.com/cloudcarver/autocerts/internal/platform/aliyun/fc"
	aliyunoss "github.com/cloudcarver/autocerts/internal/platform/aliyun/oss"
	aliyunsts "github.com/cloudcarver/autocerts/internal/platform/aliyun/sts"
	"github.com/cloudcarver/autocerts/internal/target"
)

func main() {
	fc.Start(HandleRequest)
}

func HandleRequest(event []byte) (string, error) {
	runtime, err := config.Load(event)
	if err != nil {
		return "", err
	}

	ctx := context.Background()
	service, err := buildService(runtime)
	if err != nil {
		return "", err
	}

	response := &app.Response{
		Mode:       runtime.Request.Mode,
		OccurredAt: service.Now(),
	}

	switch runtime.Request.Mode {
	case config.ModeIssue:
		result, err := service.Issue(ctx, runtime.Request)
		if err != nil {
			return "", err
		}
		response.Issue = result
	case config.ModeReconcile:
		result, err := service.Reconcile(ctx, runtime.Request)
		if err != nil {
			return "", err
		}
		response.Reconcile = result
	case config.ModeSmoke:
		result, err := service.Smoke(ctx, runtime.Request)
		if err != nil {
			return "", err
		}
		response.Smoke = result
	default:
		return "", fmt.Errorf("unsupported mode %q", runtime.Request.Mode)
	}

	payload, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal response: %w", err)
	}
	return string(payload), nil
}

func buildService(runtime *config.Runtime) (*app.Service, error) {
	service := &app.Service{
		Issuer:    acme.NewLegoIssuer(runtime.Settings),
		Threshold: runtime.Settings.CRONInterval,
		Prefix:    runtime.Settings.CertificatePrefix,
		Now: func() time.Time {
			return time.Now().UTC()
		},
	}

	needStore := false
	needALB := false
	needCDN := false
	needOSS := false
	needFC := false

	switch runtime.Request.Mode {
	case config.ModeIssue:
		needStore = true
	case config.ModeReconcile:
		needStore = true
		needALB = true
		needCDN = true
		needOSS = true
		needFC = true
	case config.ModeSmoke:
		components := runtime.Request.Components
		if len(components) == 0 {
			components = []string{"dns", "cas", "alb", "cdn", "oss", "fc"}
		}
		for _, component := range components {
			switch component {
			case "cas":
				needStore = true
			case "alb":
				needStore = true
				needALB = true
			case "cdn":
				needCDN = true
			case "oss":
				needStore = true
				needOSS = true
			case "fc":
				needFC = true
			}
		}
	}

	var (
		authProvider *aliyunauth.Provider
		store        certstore.Store
		stsClient    *aliyunsts.Client
		err          error
	)

	if needStore || needALB || needOSS || needFC {
		authProvider, err = aliyunauth.NewProvider()
		if err != nil {
			return nil, err
		}
	}

	if needStore {
		store, err = aliyuncas.NewStore(runtime.Settings.CASResourceGroupID, authProvider.Credential())
		if err != nil {
			return nil, err
		}
		service.Store = store
	}

	if needFC && runtime.Settings.AccountID == "" {
		stsClient, err = aliyunsts.NewClient(requiredSTSRegion(runtime.Settings), authProvider.Credential())
		if err != nil {
			return nil, err
		}
	}

	var sources []target.Source
	if needALB {
		sources = append(sources, aliyunalb.NewSource(runtime.Settings.Regions, authProvider.Credential(), store))
	}
	if needCDN {
		source, err := aliyuncdn.NewSource(authProvider.Credential())
		if err != nil {
			return nil, err
		}
		sources = append(sources, source)
	}
	if needOSS {
		sources = append(sources, aliyunoss.NewSource(authProvider, store))
	}
	if needFC {
		var resolver interface{ AccountID() (string, error) }
		if runtime.Settings.AccountID == "" {
			resolver = stsClient
		}
		sources = append(sources, aliyunfc.NewSource(runtime.Settings.Regions, runtime.Settings.AccountID, resolver, authProvider.Credential()))
	}
	service.Sources = sources

	return service, nil
}
func requiredSTSRegion(settings config.Settings) string {
	if len(settings.Regions) > 0 {
		return settings.Regions[0]
	}
	return ""
}
