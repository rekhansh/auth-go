package password

import (
	"fmt"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

func (p *PasswordAuthProvider) ValidateAuthToken(tokenString string) (jwt.Token, error) {
	keyset, err := p.getKeySet()
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

func (p *PasswordAuthProvider) getKeySet() (jwk.Set, error) {
	return nil, fmt.Errorf("not implemented yet")
}
