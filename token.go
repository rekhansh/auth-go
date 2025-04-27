package auth

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

const (
	ErrorTokenEmpty         = "token is empty"
	ErrorUnableToParseToken = "unable to parse token"
	ErrorIssuerEmpty        = "issuer is empty"
	ErrorIatTimeEmpty       = "iat time is empty"
	ErrorExpTimeEmpty       = "exp time is empty"
	ErrorNoProviderFound    = "no provider found for issuer %s"
)

func (a *AuthService) ValidateToken(tokenString string) (jwt.Token, error) {
	if tokenString == "" {
		return nil, fmt.Errorf(ErrorTokenEmpty)
	}

	// issuer
	token, err := getUnverifiedToken(tokenString)
	if err != nil {
		return nil, fmt.Errorf(ErrorUnableToParseToken)
	}

	// Validate token claims
	if err := validateTokenClaims(token); err != nil {
		return nil, err
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
		return nil, fmt.Errorf(ErrorNoProviderFound, issuer)
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

// ValidateTokenClaims validates the claims of a JWT token which are required for authentication.
func validateTokenClaims(token jwt.Token) error {
	// Validate Issuer
	issuer, ok := token.Issuer()
	if !ok || issuer == "" {
		return fmt.Errorf(ErrorIssuerEmpty)
	}

	// Validate Iat
	iat, ok := token.IssuedAt()
	if !ok || iat.IsZero() {
		return fmt.Errorf(ErrorIatTimeEmpty)
	}

	// Validate Exp
	exp, ok := token.Expiration()
	if !ok || exp.IsZero() {
		return fmt.Errorf(ErrorExpTimeEmpty)
	}

	// Validate other claims as needed
	// ...

	return nil
}
