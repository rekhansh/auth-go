package jwt

import (
	"fmt"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

// ValidateToken - validate token
func (j *JwtAuthProvider) ValidateToken(tokenString string) (jwt.Token, error) {
	keyset, err := j.getKeySet()
	if err != nil {
		fmt.Printf("failed to get keys")
		return nil, err
	}

	// Verify with Keyset
	token, err := jwt.Parse([]byte(tokenString), jwt.WithKeySet(keyset))
	if err != nil {
		fmt.Printf("failed to parse payload: %s\n", err)
		return nil, err
	}

	return token, nil
}

func (j *JwtAuthProvider) getKeySet() (jwk.Set, error) {
	return nil, fmt.Errorf("not implemented yet")
}
