package oidc

import (
	"testing"

	mockoidc "github.com/rekhansh/goauth/provider/oidc/mock"
	"github.com/stretchr/testify/assert"
)

func TestOidcKeySet(t *testing.T) {

	// Create a new HTTP test server
	server := mockoidc.HostMockOIDCServer()
	defer server.Close()

	oidcAuthProvider, err := NewOidcProvider(&OidcAuthProviderConfig{
		Issuer: server.URL,
	})
	assert.Nil(t, err)

	// Test
	keyset, err := oidcAuthProvider.getKeySet()
	assert.Nil(t, err, "error is not empty")
	assert.NotNil(t, keyset, "keyset is empty")
}
