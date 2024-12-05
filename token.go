package auth

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

func (a *AuthService) ValidateToken(tokenString string) (jwt.Token, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("empty token")
	}

	// issuer
	token, err := getUnverifiedToken(tokenString)
	if err != nil {
		return nil, fmt.Errorf("no issuer found")
	}

	// Find provider
	var provider AuthProvider
	for _, p := range a.providers {
		if p.IsTokenSupported(token) {
			provider = p
			break
		}
	}
	if provider == nil {
		issuer, _ := token.Issuer()
		return nil, fmt.Errorf("no provider found for issuer %s", issuer)
	}

	return provider.ValidateToken(tokenString)
}

func getUnverifiedToken(tokenString string) (jwt.Token, error) {
	token, err := jwt.ParseInsecure([]byte(tokenString))
	if err != nil {
		return nil, err
	}
	return token, nil
}
