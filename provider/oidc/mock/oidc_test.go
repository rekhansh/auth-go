package mockoidc

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"testing"

	oidcutils "github.com/rekhansh/auth/utils/oidc"
	"github.com/stretchr/testify/assert"
)

func TestOIDCMockServer(t *testing.T) {
	// Create a new HTTP test server
	mockServer := NewOIDCMockServer(nil)

	testServer := mockServer.GetTestServer()
	defer testServer.Close()

	t.Run("TestTokenGeneration", func(t *testing.T) {
		token, err := mockServer.GenerateTestToken(nil)
		assert.Nil(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("TestWellKnownUrl", func(t *testing.T) {
		// Create Request
		configUrl := testServer.URL + oidcutils.OIDCEndpointWelKnownOpenIDConfiguration
		req, err := http.NewRequest(http.MethodGet, configUrl, nil)
		assert.Nil(t, err)

		// Send Request
		resp, err := http.DefaultClient.Do(req)
		assert.Nil(t, err)

		// check resp
		if resp.StatusCode != http.StatusOK {
			respBody, err := io.ReadAll(resp.Body)
			assert.Nil(t, err)
			log.Printf("response: %v", string(respBody))
		}

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Extract Body
		var openidConfig oidcutils.OpenIDConfig
		err = json.NewDecoder(resp.Body).Decode(&openidConfig)
		assert.Nil(t, err)
		assert.NotNil(t, openidConfig)

		// Validate Require Fields
		assert.NotEmpty(t, openidConfig.JwksURI)

		t.Run("TestJwkUri", func(t *testing.T) {
			// Create Request
			req, err := http.NewRequest(http.MethodGet, openidConfig.JwksURI, nil)
			assert.Nil(t, err)

			// Send Request
			resp, err := http.DefaultClient.Do(req)
			assert.Nil(t, err)

			// check resp
			if resp.StatusCode != http.StatusOK {
				respBody, err := io.ReadAll(resp.Body)
				assert.Nil(t, err)
				log.Printf("response: %v", string(respBody))
			}

			assert.Equal(t, http.StatusOK, resp.StatusCode)

			// Extract Body
			var jwks interface{}
			err = json.NewDecoder(resp.Body).Decode(&jwks)
			assert.Nil(t, err)
			assert.NotNil(t, jwks)
		})
	})
}
