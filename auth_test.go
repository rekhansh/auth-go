package auth_test

import (
	"testing"

	"github.com/rekhansh/auth"
	"github.com/stretchr/testify/assert"
)

func TestAuthService(t *testing.T) {

	t.Run("Test Nil Config", func(t *testing.T) {
		authService := auth.New(nil)
		assert.NotNil(t, authService)
		assert.NotNil(t, authService.AuthServiceConfig)
	})

	// Test Service Defaults
	t.Run("Test Defaults", func(t *testing.T) {
		authService := auth.New(&auth.AuthServiceConfig{})
		assert.NotNil(t, authService)
		assert.Equal(t, authService.URLPrefix, auth.DefaultURLPrefix)
	})
}
