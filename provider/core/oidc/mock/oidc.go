package mockoidc

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"net/http"
	"net/http/httptest"

	"github.com/gorilla/mux"
	oidcutils "github.com/rekhansh/auth/utils/oidc"
)

type OIDCMockServerConfig struct {
	PrivateKey *rsa.PrivateKey
}

type OIDCMockServer struct {
	*OIDCMockServerConfig
}

type Route struct {
	Method  string
	Handler func(mockServer *OIDCMockServer) http.HandlerFunc
}

var RouteMap = map[string]Route{
	oidcutils.OIDCEndpointWelKnownOpenIDConfiguration: {
		Method:  http.MethodGet,
		Handler: WelKnownOpenIDConfigurationHandler,
	},
	oidcutils.OIDCEndpointAuthorization: {
		Method:  http.MethodPost,
		Handler: AuthorizationHandler,
	},
	oidcutils.OIDCEndpointToken: {
		Method:  http.MethodPost,
		Handler: TokenHandler,
	},
	oidcutils.OIDCEndpointUserInfo: {
		Method:  http.MethodPost,
		Handler: UserInfoHandler,
	},
	oidcutils.OIDCEndpointJwksUri: {
		Method:  http.MethodGet,
		Handler: JwksUriHandler,
	},
	oidcutils.OIDCEndpointRegistration: {
		Method:  http.MethodPost,
		Handler: RegistrationHandler,
	},
}

func NewOIDCMockServer(config *OIDCMockServerConfig) *OIDCMockServer {
	if config == nil {
		config = &OIDCMockServerConfig{}
	}

	if config.PrivateKey == nil {

		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Panicf("failed to generate private key: %s", err)
		}
		config.PrivateKey = key
	}

	mockServer := &OIDCMockServer{
		OIDCMockServerConfig: config,
	}

	return mockServer
}

func (mockServer *OIDCMockServer) GetTestServer() *httptest.Server {

	// Create a new router
	router := mux.NewRouter()

	// Set routes
	for path, route := range RouteMap {
		router.HandleFunc(path, route.Handler(mockServer)).Methods(route.Method)
	}

	// return server
	return httptest.NewServer(router)
}
