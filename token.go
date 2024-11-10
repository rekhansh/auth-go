package goauth

import (
	"fmt"

	"github.com/lestrrat-go/jwx/jwt"
)

func (a *AuthService) ValidateToken(tokenString string) (jwt.Token, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("empty token")
	}

	// issuer
	issuer := getUnverifiedIssuer(tokenString)
	if issuer == "" {
		return nil, fmt.Errorf("no issuer found")
	}

	// Find provider
	var provider AuthProvider
	for _, p := range a.providers {
		if p.GetIssuer() == issuer {
			provider = p
			break
		}
	}
	if provider == nil {
		return nil, fmt.Errorf("no provider found for issuer %s", issuer)
	}

	return provider.ValidateToken(tokenString)
}

func getUnverifiedIssuer(tokenString string) string {
	token, err := jwt.Parse([]byte(tokenString))
	if err != nil {
		return ""
	}
	return token.Issuer()
}
