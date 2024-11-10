package oidc

import (
	"context"
	"fmt"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

func (o *OidcAuthProvider) ValidateToken(tokenString string) (jwt.Token, error) {
	// Get KeySet
	keyset, err := o.getKeySet()
	if err != nil {
		return nil, err
	}

	// jwt
	validator := jwt.ValidatorFunc(func(_ context.Context, t jwt.Token) error {
		// if time.Now().Month() != 8 {
		// 	return fmt.Errorf(`tokens are only valid during August!`)
		// }
		return nil
	})

	// Get Token
	token, err := jwt.Parse(
		[]byte(tokenString),
		jwt.WithKeySet(keyset),
		jwt.WithIssuer(o.Issuer),
		jwt.WithValidator(validator),
	)
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
