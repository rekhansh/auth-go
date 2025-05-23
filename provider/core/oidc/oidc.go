package oidc

import (
	"errors"

	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/rekhansh/auth/keyset"
)

const (
	ErrorIssuerRequired = "issuer is required"
)

type OidcAuthProvider struct {
	*OidcAuthProviderConfig
}

type OidcAuthProviderConfig struct {
	ID              string
	Issuer          string
	KeysetDiscovery keyset.KeysetDiscovery
}

func NewOidcProvider(config *OidcAuthProviderConfig) (*OidcAuthProvider, error) {
	if config == nil {
		config = &OidcAuthProviderConfig{}
	}
	if config.Issuer == "" {
		return nil, errors.New(ErrorIssuerRequired)
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

func (o *OidcAuthProvider) GetID() string {
	if o.ID != "" {
		return o.ID
	}
	return o.Issuer
}

func (o *OidcAuthProvider) IsTokenSupported(token jwt.Token) bool {
	issuer, ok := token.Issuer()
	if ok && issuer == o.Issuer {
		return true
	}
	return false
}
