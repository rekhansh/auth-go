package auth_test

import (
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/rekhansh/goauth"
	"github.com/rekhansh/goauth/provider/okta"
	"github.com/rekhansh/goauth/provider/password"
	"github.com/stretchr/testify/assert"
)

func TestAuthService(t *testing.T) {
	initAuthService(t)

	// register auth routers to server
	router := mux.NewRouter()
	authService.RegisterRoutes(router)
	server := httptest.NewServer(router)
	defer server.Close()

}

var authService *goauth.AuthService

func initAuthService(t *testing.T) {
	authService = goauth.New(&goauth.AuthServiceConfig{})

	// setup providers
	registerPasswordProvider(t)
	registerOktaProvider(t)
}

func registerPasswordProvider(t *testing.T) {
	//
	provider, err := password.NewPasswordAuthProvider(nil)
	assert.Nil(t, err)
	if err != nil {
		authService.RegisterProvider(provider)
	}
}

func registerOktaProvider(t *testing.T) {
	//
	provider, err := okta.NewOktaProvider(nil)
	assert.Nil(t, err)
	if err != nil {
		authService.RegisterProvider(provider)
	}
}
