package auth

import (
	"fmt"

	"github.com/gorilla/mux"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type AuthProvider interface {
	GetID() string
	RegisterRoutes(router *mux.Router)
	ValidateToken(token string) (jwt.Token, error)
	IsTokenSupported(token jwt.Token) bool
}

func (a *AuthService) RegisterProvider(provider AuthProvider) error {
	if provider == nil {
		return fmt.Errorf("provider is nil")
	}
	if provider.GetID() == "" {
		return fmt.Errorf("provider id is empty")
	}
	for _, p := range a.providers {
		if p.GetID() == provider.GetID() {
			return fmt.Errorf("provider with id %s already exists", provider.GetID())
		}
	}
	return nil
}
