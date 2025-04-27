package oidc

import (
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

const (
	ErrorKeysetNotFound     = "keyset not found"
	ErrorFailedToParseToken = "failed to parse token"
)

func (o *OidcAuthProvider) ValidateToken(tokenString string) (jwt.Token, error) {
	// Get KeySet
	if o.KeysetDiscovery == nil {
		return nil, errors.New(ErrorKeysetNotFound)
	}

	// Get Keyset
	keyset, err := o.KeysetDiscovery.GetKeyset()
	if err != nil {
		return nil, err
	}

	// Get Token
	token, err := jwt.Parse([]byte(tokenString), jwt.WithKeySet(keyset))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ErrorFailedToParseToken, err)
	}

	return token, nil
}
