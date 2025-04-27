package oidc_test

import (
	"strings"
	"testing"

	"github.com/rekhansh/auth/provider/core/oidc"
	mockoidc "github.com/rekhansh/auth/provider/core/oidc/mock"
	"github.com/stretchr/testify/assert"
)

func TestValidateToken(t *testing.T) {

	t.Run("Nil Keyset Discovery", func(t *testing.T) {
		oidcProvider, err := oidc.NewOidcProvider(&oidc.OidcAuthProviderConfig{
			Issuer: "test-issuer",
		})
		assert.Nil(t, err)
		assert.NotNil(t, oidcProvider)
		oidcProvider.KeysetDiscovery = nil
		token, err := oidcProvider.ValidateToken("test-token")
		assert.NotNil(t, err)
		assert.Equal(t, err.Error(), oidc.ErrorKeysetNotFound)
		assert.Nil(t, token)
	})

	t.Run("Valid Keyset Discovery", func(t *testing.T) {
		oidcProvider, err := oidc.NewOidcProvider(&oidc.OidcAuthProviderConfig{
			Issuer: "test-issuer",
		})
		assert.Nil(t, err)
		assert.NotNil(t, oidcProvider)
		token, err := oidcProvider.ValidateToken("test-token")
		assert.NotNil(t, err)
		assert.Nil(t, token)
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

		t.Run("TestToken", func(t *testing.T) {
			jwtToken, err := oidcProvider.ValidateToken("token")
			assert.NotNil(t, err)
			assert.Nil(t, jwtToken)
			if !strings.Contains(err.Error(), oidc.ErrorFailedToParseToken) {
				assert.Equal(t, err.Error(), oidc.ErrorFailedToParseToken)
			}
		})

		t.Run("Validate Token", func(t *testing.T) {
			jwtToken, err := oidcProvider.ValidateToken(token)
			assert.Nil(t, err)
			assert.NotNil(t, jwtToken)
		})
	})
}
