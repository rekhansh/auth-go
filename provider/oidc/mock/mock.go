package mockoidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/rekhansh/auth/config"
)

const (
	wellKnownUrlPath = "/.well-known/openid-configuration"
	jwksUrlPath      = "/admin/v1/SigningCert/jwk"
)

func generateOpenIDConfig(baseURL string) config.OpenIDConfig {
	return config.OpenIDConfig{
		Issuer:  baseURL,
		JwksURI: baseURL + jwksUrlPath,
	}
}

func HostMockOIDCServer() *httptest.Server {
	serverMux := http.NewServeMux()
	serverMux.HandleFunc(wellKnownUrlPath, openIDConfigHandler)
	serverMux.HandleFunc(jwksUrlPath, generateJWKHandler)
	return httptest.NewServer(serverMux)
}

func openIDConfigHandler(w http.ResponseWriter, r *http.Request) {
	config := generateOpenIDConfig("http://" + r.Host)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(config); err != nil {
		http.Error(w, "Failed to encode OpenID config", http.StatusInternalServerError)
	}
}

func generateJWKHandler(w http.ResponseWriter, r *http.Request) {
	// Create a JWK set
	keySet := jwk.NewSet()

	// Set response headers
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Encode the JWK set as JSON and write it to the response
	if err := json.NewEncoder(w).Encode(keySet); err != nil {
		http.Error(w, "Failed to encode JWK", http.StatusInternalServerError)
	}
}
