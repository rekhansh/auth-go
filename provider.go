package auth

import (
	"fmt"

	"github.com/gorilla/mux"
	"github.com/lestrrat-go/jwx/jwt"
)

type AuthProvider interface {
	GetIssuer() string
	RegisterRoutes(router *mux.Router)
	ValidateToken(token string) (jwt.Token, error)
}

func (a *AuthService) RegisterProvider(provider AuthProvider) error {
	if provider == nil {
		return fmt.Errorf("provider is nil")
	}
	if provider.GetIssuer() == "" {
		return fmt.Errorf("provider issuer is empty")
	}
	for _, p := range a.providers {
		if p.GetIssuer() == provider.GetIssuer() {
			return fmt.Errorf("provider with issuer %s already exists", provider.GetIssuer())
		}
	}
	return nil
}
