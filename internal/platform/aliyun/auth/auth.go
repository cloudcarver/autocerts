package auth

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/alibabacloud-go/tea/tea"
	osscredentials "github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss/credentials"
	credential "github.com/aliyun/credentials-go/credentials"
)

type Provider struct {
	credential credential.Credential
}

type CredentialSnapshot struct {
	AccessKeyID     string
	AccessKeySecret string
	SecurityToken   string
}

func NewProvider() (*Provider, error) {
	if cred, ok, err := explicitCredentialFromEnv(); err != nil {
		return nil, err
	} else if ok {
		return &Provider{credential: cred}, nil
	}

	cred, err := credential.NewCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("create default aliyun credential: %w", err)
	}

	return &Provider{credential: cred}, nil
}

func (p *Provider) Credential() credential.Credential {
	return p.credential
}

func (p *Provider) CredentialSnapshot() (*CredentialSnapshot, error) {
	actual, err := p.credential.GetCredential()
	if err != nil {
		return nil, err
	}
	return &CredentialSnapshot{
		AccessKeyID:     tea.StringValue(actual.AccessKeyId),
		AccessKeySecret: tea.StringValue(actual.AccessKeySecret),
		SecurityToken:   tea.StringValue(actual.SecurityToken),
	}, nil
}

func (p *Provider) OSSCredentialsProvider() osscredentials.CredentialsProvider {
	return osscredentials.CredentialsProviderFunc(func(_ context.Context) (osscredentials.Credentials, error) {
		actual, err := p.CredentialSnapshot()
		if err != nil {
			return osscredentials.Credentials{}, err
		}

		return osscredentials.Credentials{
			AccessKeyID:     actual.AccessKeyID,
			AccessKeySecret: actual.AccessKeySecret,
			SecurityToken:   actual.SecurityToken,
		}, nil
	})
}

func explicitCredentialFromEnv() (credential.Credential, bool, error) {
	accessKeyID := firstNonEmpty(
		os.Getenv("ALIYUN_ACCESS_KEY_ID"),
		os.Getenv("ALIYUN_AK"),
	)
	accessKeySecret := firstNonEmpty(
		os.Getenv("ALIYUN_ACCESS_KEY_SECRET"),
		os.Getenv("ALIYUN_SK"),
	)
	securityToken := firstNonEmpty(
		os.Getenv("ALIYUN_SECURITY_TOKEN"),
		os.Getenv("ALIYUN_STS_TOKEN"),
	)

	if accessKeyID == "" && accessKeySecret == "" {
		return nil, false, nil
	}
	if accessKeyID == "" || accessKeySecret == "" {
		return nil, false, fmt.Errorf("ALIYUN access key ID/secret must be provided together")
	}

	cfg := new(credential.Config).SetAccessKeyId(accessKeyID).SetAccessKeySecret(accessKeySecret)
	if strings.TrimSpace(securityToken) != "" {
		cfg.SetType("sts").SetSecurityToken(securityToken)
	} else {
		cfg.SetType("access_key")
	}

	cred, err := credential.NewCredential(cfg)
	if err != nil {
		return nil, false, fmt.Errorf("create explicit aliyun credential: %w", err)
	}
	return cred, true, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
