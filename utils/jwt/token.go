package jwtutils

import (
	"log"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Generate JWT Token
func GenerateToken(claims map[string]interface{}, key interface{}) (string, error) {
	token := jwt.New()
	for key, value := range claims {
		if err := token.Set(key, value); err != nil {
			return "", err
		}
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256(), key))
	if err != nil {
		log.Printf("failed to sign token: %s", err)
		return "", err
	}
	return string(signed), nil
}
