package oidc

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

func (o *OidcAuthProvider) ValidateToken(tokenString string) (jwt.Token, error) {
	// Get KeySet
	keyset, err := o.getKeySet()
	if err != nil {
		return nil, err
	}

	// Get Token
	token, err := jwt.Parse([]byte(tokenString), jwt.WithKeySet(keyset))
	if err != nil {
		fmt.Printf("failed to parse payload: %s\n", err)
	}

	return token, nil
}

func (o *OidcAuthProvider) getKeySet() (jwk.Set, error) {
	if o.KeysetDiscovery != nil {
		return o.KeysetDiscovery.GetKeyset()
	}
	return nil, fmt.Errorf("unable to get keys to validate")
}
