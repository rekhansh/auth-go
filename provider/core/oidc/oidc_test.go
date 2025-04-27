package oidc_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/rekhansh/auth/provider/core/oidc"
	mockoidc "github.com/rekhansh/auth/provider/core/oidc/mock"
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
	t.Run("Valid Service", func(t *testing.T) {
		// Create a new HTTP test server
		mockServer := mockoidc.NewOIDCMockServer(nil)
		testServer := mockServer.GetTestServer()
		defer testServer.Close()
		oidcProvider, err := oidc.NewOidcProvider(&oidc.OidcAuthProviderConfig{
			Issuer: testServer.URL,
		})
		assert.Nil(t, err)
		assert.Equal(t, oidcProvider.GetID(), testServer.URL)
		assert.Equal(t, oidcProvider.Issuer, testServer.URL)
	})

	// Generate Token
	t.Run("TestTokenGeneration", func(t *testing.T) {
		mockServer := mockoidc.NewOIDCMockServer(nil)
		testServer := mockServer.GetTestServer()
		defer testServer.Close()
		// Provider
		oidcProvider, err := oidc.NewOidcProvider(&oidc.OidcAuthProviderConfig{
			Issuer: testServer.URL,
		})
		assert.Nil(t, err)
		token, err := mockServer.GenerateTestToken(nil)
		assert.Nil(t, err)

		t.Run("Is Token Supported", func(t *testing.T) {
			jwtToken := jwt.New()
			jwtToken.Set(jwt.IssuerKey, testServer.URL)
			ok := oidcProvider.IsTokenSupported(jwtToken)
			assert.True(t, ok)

			jwtTokenFail := jwt.New()
			ok = oidcProvider.IsTokenSupported(jwtTokenFail)
			assert.False(t, ok)
		})

		t.Run("Validate Token", func(t *testing.T) {
			jwtToken, err := oidcProvider.ValidateToken(token)
			assert.Nil(t, err)
			assert.NotNil(t, jwtToken)
		})
	})
	//
}
