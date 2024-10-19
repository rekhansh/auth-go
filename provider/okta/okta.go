package okta

import "github.com/rekhansh/goauth"

type OktaAuthProvider struct {
	*OktaAuthProviderConfig
}

type OktaAuthProviderConfig struct {
	goauth.AuthProviderConfig
}

func NewOktaProvider(config *OktaAuthProviderConfig) (*OktaAuthProvider, error) {
	if config == nil {
		config = &OktaAuthProviderConfig{}
	}
	if config.Issuer == "" {
		config.Issuer = "oidc"
	}

	oktaAuthProvider := &OktaAuthProvider{
		OktaAuthProviderConfig: config,
	}
	return oktaAuthProvider, nil
}

func (o *OktaAuthProvider) GetIssuer() string {
	return o.Issuer
}
