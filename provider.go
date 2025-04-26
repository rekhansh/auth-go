package auth

import (
	"fmt"

	"github.com/gorilla/mux"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

const (
	ErrorProviderNil           = "provider is nil"
	ErrorEmptyProviderID       = "provider id is empty"
	ErrorProviderAlreadyExists = "provider with id %s already exists"
)

type AuthProvider interface {
	GetID() string
	RegisterRoutes(router *mux.Router)
	ValidateToken(token string) (jwt.Token, error)
	IsTokenSupported(token jwt.Token) bool
}

// RegisterProvider registers a new authentication provider with the AuthService.
func (a *AuthService) RegisterProvider(provider AuthProvider) error {
	if provider == nil {
		return fmt.Errorf(ErrorProviderNil)
	}
	if provider.GetID() == "" {
		return fmt.Errorf(ErrorEmptyProviderID)
	}
	// Check if the provider already exists
	_, ok := a.providers[provider.GetID()]
	if ok {
		return fmt.Errorf(ErrorProviderAlreadyExists, provider.GetID())
	}

	// Register the provider
	a.providers[provider.GetID()] = provider
	return nil
}
