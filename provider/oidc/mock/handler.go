package mockoidc

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	oidcutils "github.com/rekhansh/auth/utils/oidc"
)

func WelKnownOpenIDConfigurationHandler(mockServer *OIDCMockServer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		serverUrl := fmt.Sprintf("http://%s", r.Host)
		config := oidcutils.OpenIDConfig{
			Issuer:  serverUrl,
			JwksURI: fmt.Sprintf("%s%s", serverUrl, oidcutils.OIDCEndpointJwksUri),
		}

		// Write the response
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(config)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
		}
	}
}

func AuthorizationHandler(mockServer *OIDCMockServer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
	}
}

func TokenHandler(mockServer *OIDCMockServer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
	}
}

func UserInfoHandler(mockServer *OIDCMockServer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
	}
}

func JwksUriHandler(mockServer *OIDCMockServer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jwkKey, err := jwk.Import(mockServer.PrivateKey)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
		}

		jwkKey.Set(jwk.KeyIDKey, testKeyID)
		jwkKey.Set(jwk.AlgorithmKey, jwa.RS256())

		jwks := jwk.NewSet()
		jwks.AddKey(jwkKey)

		publicSet, err := jwk.PublicSetOf(jwks)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
		}

		// Write the response
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		err = json.NewEncoder(w).Encode(publicSet)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
		}
	}
}
func RegistrationHandler(mockServer *OIDCMockServer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotImplemented)
	}
}
