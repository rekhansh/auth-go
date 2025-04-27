package keyset_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rekhansh/auth/keyset"
	oidcutils "github.com/rekhansh/auth/utils/oidc"
)

func TestOidcKeySetDiscovery(t *testing.T) {
	t.Run("Empty Url", func(t *testing.T) {
		// Mock implementation of the KeysetDiscovery interface
		mockKeyset := &keyset.OidcKeysetDiscovery{
			BaseUrl: "",
		}

		set, err := mockKeyset.GetKeyset()
		if err == nil {
			t.Errorf("Expected error, got keyset: %v", set)
		}
		if err.Error() != keyset.ErrorEmptyBaseUrl {
			t.Errorf("Expected error message: %s, got: %s", keyset.ErrorEmptyBaseUrl, err.Error())
		}
	})

	t.Run("Wrong Url", func(t *testing.T) {
		// Mock implementation of the KeysetDiscovery interface
		mockKeyset := &keyset.OidcKeysetDiscovery{
			BaseUrl: "test",
		}

		set, err := mockKeyset.GetKeyset()
		if err == nil {
			t.Errorf("Expected error, got keyset: %v", set)
		}
		if !strings.Contains(err.Error(), keyset.ErrorFailedToFetchMetadata) {
			t.Errorf("Expected error message: %s, got: %s", keyset.ErrorFailedToFetchMetadata, err.Error())
		}
	})

	t.Run("Wrong Status Code", func(t *testing.T) {

		// Start a mock server to simulate the OIDC discovery endpoint
		mux := http.NewServeMux()
		server := httptest.NewServer(mux)

		// Mock implementation of the KeysetDiscovery interface
		mockKeyset := &keyset.OidcKeysetDiscovery{
			BaseUrl: server.URL,
		}

		set, err := mockKeyset.GetKeyset()
		if err == nil {
			t.Errorf("Expected error, got keyset: %v", set)
		}
		// Will have 400 status code
		if !strings.Contains(err.Error(), keyset.ErrorUnexpectedStatusCode) {
			t.Errorf("Expected error message: %s, got: %s", keyset.ErrorUnexpectedStatusCode, err.Error())
		}

		server.Close()
	})

	t.Run("Wrong Reponse", func(t *testing.T) {

		// Start a mock server to simulate the OIDC discovery endpoint
		mux := http.NewServeMux()
		mux.HandleFunc(oidcutils.OIDCEndpointWelKnownOpenIDConfiguration, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Wrong Json"))
		})
		server := httptest.NewServer(mux)

		// Mock implementation of the KeysetDiscovery interface
		mockKeyset := &keyset.OidcKeysetDiscovery{
			BaseUrl: server.URL,
		}

		set, err := mockKeyset.GetKeyset()
		if err == nil {
			t.Errorf("Expected error, got keyset: %v", set)
		}
		if !strings.Contains(err.Error(), keyset.ErrorFailedToUnmarshal) {
			t.Errorf("Expected error message: %s, got: %s", keyset.ErrorFailedToUnmarshal, err.Error())
		}

		server.Close()
	})

	t.Run("Fail to Read Body", func(t *testing.T) {
		// Start a mock server to simulate the OIDC discovery endpoint
		mux := http.NewServeMux()
		mux.HandleFunc(oidcutils.OIDCEndpointWelKnownOpenIDConfiguration, func(w http.ResponseWriter, r *http.Request) {

			w.Header().Add("Content-Length", "10")
			w.WriteHeader(http.StatusOK)
		})
		server := httptest.NewServer(mux)

		// Mock implementation of the KeysetDiscovery interface
		mockKeyset := &keyset.OidcKeysetDiscovery{
			BaseUrl: server.URL,
		}

		set, err := mockKeyset.GetKeyset()
		if err == nil {
			t.Errorf("Expected error, got keyset: %v", set)
		}
		if !strings.Contains(err.Error(), keyset.ErrorFailedToReadBody) {
			t.Errorf("Expected error message: %s, got: %s", keyset.ErrorFailedToReadBody, err.Error())
		}
		server.Close()
	})

	t.Run("Keyset Url Empy", func(t *testing.T) {
		// Start a mock server to simulate the OIDC discovery endpoint
		mux := http.NewServeMux()
		mux.HandleFunc(oidcutils.OIDCEndpointWelKnownOpenIDConfiguration, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"jwks_uri": ""}`))
		})
		server := httptest.NewServer(mux)

		// Mock implementation of the KeysetDiscovery interface
		mockKeyset := &keyset.OidcKeysetDiscovery{
			BaseUrl: server.URL,
		}

		set, err := mockKeyset.GetKeyset()
		if err == nil {
			t.Errorf("Expected error, got keyset: %v", set)
		}
		if !strings.Contains(err.Error(), keyset.ErrorKeysetUrlEmpty) {
			t.Errorf("Expected error message: %s, got: %s", keyset.ErrorKeysetUrlEmpty, err.Error())
		}

		server.Close()
	})

	t.Run("Key Url Not Found", func(t *testing.T) {
		// Start a mock server to simulate the OIDC discovery endpoint
		mux := http.NewServeMux()
		mux.HandleFunc(oidcutils.OIDCEndpointWelKnownOpenIDConfiguration, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"jwks_uri": "http://` + r.Host + oidcutils.OIDCEndpointJwksUri + `"}`))
		})
		server := httptest.NewServer(mux)

		// Mock implementation of the KeysetDiscovery interface
		mockKeyset := &keyset.OidcKeysetDiscovery{
			BaseUrl: server.URL,
		}

		// Mock the keyset URL to a non-existent endpoint
		set, err := mockKeyset.GetKeyset()
		if err == nil {
			t.Errorf("Expected error, got keyset: %v", set)
		}

		// Check if the error message contains the expected text
		if !strings.Contains(err.Error(), keyset.ErrorFailedToFetchKeyset) {
			t.Errorf("Expected error message: %s, got: %s", keyset.ErrorFailedToFetchKeyset, err.Error())
		}
		server.Close()
	})

	t.Run("Success", func(t *testing.T) {
		// Start a mock server to simulate the OIDC discovery endpoint
		mux := http.NewServeMux()
		mux.HandleFunc(oidcutils.OIDCEndpointWelKnownOpenIDConfiguration, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"jwks_uri": "http://` + r.Host + oidcutils.OIDCEndpointJwksUri + `"}`))
		})
		mux.HandleFunc(oidcutils.OIDCEndpointJwksUri, func(w http.ResponseWriter, r *http.Request) {})
		server := httptest.NewServer(mux)

		// Mock implementation of the KeysetDiscovery interface
		mockKeyset := &keyset.OidcKeysetDiscovery{
			BaseUrl: server.URL,
		}

		// Mock the keyset URL to a non-existent endpoint
		set, err := mockKeyset.GetKeyset()
		if err == nil {
			t.Errorf("Expected error, got keyset: %v", set)
		}

		// Check if the error message contains the expected text
		if !strings.Contains(err.Error(), keyset.ErrorFailedToFetchKeyset) {
			t.Errorf("Expected error message: %s, got: %s", keyset.ErrorFailedToFetchKeyset, err.Error())
		}

		if set == nil {
			t.Errorf("Expected keyset, got nil")
		}
		if len(set.Keys()) != 0 {
			t.Errorf("Expected empty keyset, got %d keys", len(set.Keys()))
		}
		server.Close()
	})

}
