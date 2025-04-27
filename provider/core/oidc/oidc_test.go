package oidc_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/rekhansh/auth/provider/core/oidc"
	"github.com/stretchr/testify/assert"
)

func TestOIDCProvider(t *testing.T) {

	// Test Nil Config
	t.Run("Nil Config", func(t *testing.T) {
		oidcProvider, err := oidc.NewOidcProvider(nil)
		assert.Nil(t, oidcProvider)
		assert.NotNil(t, err)
		assert.Equal(t, err.Error(), oidc.ErrorIssuerRequired)
	})

	// Test Service Defaults
	t.Run("Missing Issuer", func(t *testing.T) {
		oidcProvider, err := oidc.NewOidcProvider(&oidc.OidcAuthProviderConfig{})
		assert.Nil(t, oidcProvider)
		assert.NotNil(t, err)
		assert.Equal(t, err.Error(), oidc.ErrorIssuerRequired)
	})

	// Test Service Initialization
	t.Run("Valid Service without ID", func(t *testing.T) {
		oidcProvider, err := oidc.NewOidcProvider(&oidc.OidcAuthProviderConfig{
			Issuer: "test-issuer",
		})
		assert.Nil(t, err)
		assert.Equal(t, oidcProvider.GetID(), "test-issuer")
		assert.Equal(t, oidcProvider.Issuer, "test-issuer")
	})

	t.Run("Valid Service with ID", func(t *testing.T) {
		oidcProvider, err := oidc.NewOidcProvider(&oidc.OidcAuthProviderConfig{
			Issuer: "test-issuer",
			ID:     "test-id",
		})
		assert.Nil(t, err)
		assert.Equal(t, oidcProvider.GetID(), "test-id")
		assert.Equal(t, oidcProvider.Issuer, "test-issuer")
	})

	t.Run("Is Token Supported", func(t *testing.T) {
		oidcProvider, err := oidc.NewOidcProvider(&oidc.OidcAuthProviderConfig{
			Issuer: "test-issuer",
		})
		assert.Nil(t, err)
		jwtToken := jwt.New()
		jwtToken.Set(jwt.IssuerKey, "test-issuer")
		ok := oidcProvider.IsTokenSupported(jwtToken)
		assert.True(t, ok)

		jwtTokenFail := jwt.New()
		ok = oidcProvider.IsTokenSupported(jwtTokenFail)
		assert.False(t, ok)
	})
}
