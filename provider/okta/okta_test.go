package okta

import (
	"testing"

	"github.com/rekhansh/goauth"
	mockokta "github.com/rekhansh/goauth/provider/okta/mock"
	"github.com/stretchr/testify/assert"
)

func TestOktaKeySet(t *testing.T) {

	// Create a new HTTP test server
	server := mockokta.HostMockOktaServer()
	defer server.Close()

	oktaAuthProvider, err := NewOktaProvider(&OktaAuthProviderConfig{
		AuthProviderConfig: goauth.AuthProviderConfig{
			Issuer: server.URL,
		},
	})
	assert.Nil(t, err)

	// Test
	keyset, err := oktaAuthProvider.getKeySet()
	assert.Nil(t, err, "error is not empty")
	assert.NotNil(t, keyset, "keyset is empty")
}
