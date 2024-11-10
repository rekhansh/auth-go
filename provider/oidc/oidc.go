package oidc

import (
	"fmt"

	"github.com/rekhansh/goauth/keyset"
)

type OidcAuthProvider struct {
	*OidcAuthProviderConfig
}

type OidcAuthProviderConfig struct {
	Issuer          string
	KeysetDiscovery keyset.KeysetDiscovery
}

func NewOidcProvider(config *OidcAuthProviderConfig) (*OidcAuthProvider, error) {
	if config == nil {
		config = &OidcAuthProviderConfig{}
	}
	if config.Issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}

	if config.KeysetDiscovery == nil {
		config.KeysetDiscovery = &keyset.OidcKeysetDiscovery{
			BaseUrl: config.Issuer,
		}
	}

	oidcAuthProvider := &OidcAuthProvider{
		OidcAuthProviderConfig: config,
	}
	return oidcAuthProvider, nil
}

func (o *OidcAuthProvider) GetIssuer() string {
	return o.Issuer
}
