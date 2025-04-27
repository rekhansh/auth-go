package jwtutils_test

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwt"
	jwtutils "github.com/rekhansh/auth/utils/jwt"
)

func TestTokenGenerate(t *testing.T) {
	// Generate a test rsa.PrivateKey
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("failed to generate key: %s", err)
	}

	t.Run("Generate Token Key Error", func(t *testing.T) {
		claims := map[string]interface{}{}
		token, err := jwtutils.GenerateToken(claims, "key")
		if err == nil {
			t.Errorf("Expected error, got token: %s", token)
		}
	})

	t.Run("Generate Token Claim Error", func(t *testing.T) {
		claims := map[string]interface{}{
			"iss": 2,
		}
		token, err := jwtutils.GenerateToken(claims, key)
		if err == nil {
			t.Errorf("Expected error, got token: %s", token)
		}
	})

	// Generate a token
	t.Run("Generate Empty Token", func(t *testing.T) {
		claims := map[string]interface{}{}
		token, err := jwtutils.GenerateToken(claims, key)
		if err != nil {
			t.Errorf("Error generating token: %v", err)
		}
		if token == "" {
			t.Errorf("Generated token is empty")
		}
	})

	// Generate a token with claims
	t.Run("Generate Token with Claims", func(t *testing.T) {
		claims := map[string]interface{}{
			"sub": "1234567890",
		}
		token, err := jwtutils.GenerateToken(claims, key)
		if err != nil {
			t.Errorf("Error generating token: %v", err)
		}
		if token == "" {
			t.Errorf("Generated token is empty")
		}

		// Validate the claims
		unverified, err := jwt.ParseInsecure([]byte(token))
		if err != nil {
			t.Errorf("Error parsing token: %v", err)
		}
		if unverified == nil {
			t.Errorf("Parsed token is nil")
		}

		for k, v := range claims {
			var value interface{}
			err = unverified.Get(k, &value)
			if err != nil {
				t.Errorf("Error getting claim %s: %v", k, err)
			}
			if value != v {
				t.Errorf("Expected claim %s to be %v, got %v", k, v, value)
			}
		}
	})

}
