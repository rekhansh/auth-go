package auth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"testing"
	"time"

	"github.com/rekhansh/auth"
	jwtutils "github.com/rekhansh/auth/utils/jwt"
	"github.com/stretchr/testify/assert"
)

func TestAuthToken(t *testing.T) {
	authService := auth.New(&auth.AuthServiceConfig{})
	assert.NotNil(t, authService)

	// Register mock provider
	mockProvider := &MockAuthProvider{ID: "mock-provider"}
	err := authService.RegisterProvider(mockProvider)
	assert.NoError(t, err)

	// Generate a test rsa.PrivateKey
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("failed to generate key: %s", err)
	}

	// 1. Check Empty Token
	t.Run("Empty Token", func(t *testing.T) {
		tokenStr := ""
		token, err := authService.ValidateToken(tokenStr)
		assert.Error(t, err, auth.ErrorTokenEmpty)
		assert.Nil(t, token)
	})

	// 2. Check with Token
	t.Run("Invalid Jwt Token", func(t *testing.T) {
		verifiedToken, err := authService.ValidateToken("token")
		assert.Nil(t, verifiedToken)
		assert.Error(t, err, auth.ErrorUnableToParseToken)
	})

	t.Run("Empty Issuer in Token", func(t *testing.T) {
		claims := map[string]interface{}{}
		token, err := jwtutils.GenerateToken(claims, key)
		if err != nil || token == "" {
			t.Errorf("Error generating token: %v", err)
		}

		verifiedToken, err := authService.ValidateToken(token)
		assert.Nil(t, verifiedToken)
		assert.Error(t, err, auth.ErrorIssuerEmpty)
	})

	t.Run("Empty Iat in Token", func(t *testing.T) {
		claims := map[string]interface{}{
			"iss": "issuer",
		}
		token, err := jwtutils.GenerateToken(claims, key)
		if err != nil || token == "" {
			t.Errorf("Error generating token: %v", err)
		}

		verifiedToken, err := authService.ValidateToken(token)
		assert.Nil(t, verifiedToken)
		assert.Error(t, err, auth.ErrorIatTimeEmpty)
	})

	t.Run("Empty Exp in Token", func(t *testing.T) {
		currentTime := time.Now()
		claims := map[string]interface{}{
			"iss": "issuer",
			"iat": currentTime.Unix(),
		}
		token, err := jwtutils.GenerateToken(claims, key)
		if err != nil || token == "" {
			t.Errorf("Error generating token: %v", err)
		}

		verifiedToken, err := authService.ValidateToken(token)
		assert.Nil(t, verifiedToken)
		assert.Error(t, err, auth.ErrorExpTimeEmpty)
	})

	t.Run("Valid Token without supported provider", func(t *testing.T) {
		currentTime := time.Now()
		claims := map[string]interface{}{
			"iss": "issuer",
			"iat": currentTime.Unix(),
			"exp": currentTime.Add(1 * time.Hour).Unix(),
		}
		token, err := jwtutils.GenerateToken(claims, key)
		if err != nil || token == "" {
			t.Errorf("Error generating token: %v", err)
		}

		verifiedToken, err := authService.ValidateToken(token)
		assert.Nil(t, verifiedToken)
		assert.Error(t, err, auth.ErrorNoProviderFound, claims["iss"])
	})

	t.Run("Valid Token with supported provider", func(t *testing.T) {
		currentTime := time.Now()
		claims := map[string]interface{}{
			"iss": mockProvider.ID,
			"iat": currentTime.Unix(),
			"exp": currentTime.Add(1 * time.Hour).Unix(),
		}
		token, err := jwtutils.GenerateToken(claims, key)
		if err != nil || token == "" {
			t.Errorf("Error generating token: %v", err)
		}

		verifiedToken, err := authService.ValidateToken(token)
		assert.NoError(t, err)
		assert.NotNil(t, verifiedToken)

		// Validate the claims
		issuer, ok := verifiedToken.Issuer()
		if !ok || issuer != claims["iss"] {
			t.Errorf("Expected issuer %s, got %s", claims["iss"], issuer)
		}
	})
}
