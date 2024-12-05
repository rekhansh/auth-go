package oidc

import (
	"testing"

	mockoidc "github.com/rekhansh/auth/provider/oidc/mock"
	"github.com/stretchr/testify/assert"
)

func TestOIDCProvider(t *testing.T) {

	// Create a new HTTP test server
	mockServer := mockoidc.NewOIDCMockServer(nil)

	testServer := mockServer.GetTestServer()
	defer testServer.Close()

	// Provider
	oidcProvider, err := NewOidcProvider(&OidcAuthProviderConfig{
		Issuer: testServer.URL,
	})
	assert.Nil(t, err)
	assert.NotNil(t, oidcProvider)

	// Generate Token
	t.Run("TestTokenGeneration", func(t *testing.T) {
		token, err := mockServer.GenerateTestToken(nil)
		assert.Nil(t, err)

		t.Run("Validate Token", func(t *testing.T) {
			jwtToken, err := oidcProvider.ValidateToken(token)
			assert.Nil(t, err)
			assert.NotNil(t, jwtToken)
		})
	})
	//
}
