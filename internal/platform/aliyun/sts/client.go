package sts

import (
	"fmt"
	"sync"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/utils"
	stssdk "github.com/alibabacloud-go/sts-20150401/v2/client"
	"github.com/alibabacloud-go/tea/tea"
	credential "github.com/aliyun/credentials-go/credentials"
)

type clientAPI interface {
	GetCallerIdentity() (*stssdk.GetCallerIdentityResponse, error)
}

type Client struct {
	client clientAPI

	once      sync.Once
	accountID string
	err       error
}

func NewClient(region string, credentialClient credential.Credential) (*Client, error) {
	cfg := new(openapi.Config).SetRegionId(region).SetCredential(credentialClient)
	client, err := stssdk.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("create STS client: %w", err)
	}
	return &Client{client: client}, nil
}

func NewClientWithAPI(client clientAPI) *Client {
	return &Client{client: client}
}

func (c *Client) AccountID() (string, error) {
	c.once.Do(func() {
		response, err := c.client.GetCallerIdentity()
		if err != nil {
			c.err = fmt.Errorf("get caller identity: %w", err)
			return
		}
		c.accountID = tea.StringValue(response.Body.AccountId)
		if c.accountID == "" {
			c.err = fmt.Errorf("account ID is empty in STS response")
		}
	})

	return c.accountID, c.err
}
