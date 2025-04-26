package auth_test

import (
	"testing"

	"github.com/rekhansh/auth"
	"github.com/stretchr/testify/assert"
)

func TestAuthService(t *testing.T) {
	authService := auth.New(&auth.AuthServiceConfig{})
	assert.NotNil(t, authService)

	// Test Service Defaults
	t.Run("Test Defaults", func(t *testing.T) {
		assert.Equal(t, authService.URLPrefix, auth.DefaultURLPrefix)
	})
}
