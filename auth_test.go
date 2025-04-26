package auth_test

import (
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/rekhansh/auth"
	"github.com/stretchr/testify/assert"
)

// MockAuthProvider is a mock implementation of the AuthProvider interface
type MockAuthProvider struct {
	ID string
}

func (m *MockAuthProvider) GetID() string {
	return m.ID
}

func (m *MockAuthProvider) RegisterRoutes(router *mux.Router) {
	// Mock implementation, no routes to register
}

func (m *MockAuthProvider) ValidateToken(token string) (jwt.Token, error) {
	// Mock implementation, always return nil
	return nil, nil
}

func (m *MockAuthProvider) IsTokenSupported(token jwt.Token) bool {
	// Mock implementation, always return false
	return false
}

func TestAuthService(t *testing.T) {
	// register auth routers to server
	router := mux.NewRouter()
	authService := auth.New(&auth.AuthServiceConfig{})
	assert.NotNil(t, authService)
	server := httptest.NewServer(router)
	defer server.Close()

	// 1. Register Auth Provider
	t.Run("Register Auth Provider", func(t *testing.T) {
		// 1.1 Register Provider - nil
		t.Run("RegisterProviderNil", func(t *testing.T) {
			err := authService.RegisterProvider(nil)
			assert.Error(t, err, auth.ErrorProviderNil)
		})

		// 1.2 Register Provider - Empty ID
		t.Run("RegisterProviderEmptyID", func(t *testing.T) {
			err := authService.RegisterProvider(&MockAuthProvider{ID: ""})
			assert.Error(t, err, auth.ErrorEmptyProviderID)
		})

		// 1.3 Register Provider - Already Exists
		t.Run("RegisterProviderAlreadyExists", func(t *testing.T) {
			provider := &MockAuthProvider{ID: "test-provider"}
			err := authService.RegisterProvider(provider)
			assert.NoError(t, err)

			err = authService.RegisterProvider(provider)
			assert.Error(t, err, auth.ErrorProviderAlreadyExists)
		})

		// 1.4 Register Provider - Valid
		t.Run("RegisterProviderValid", func(t *testing.T) {
			provider := &MockAuthProvider{ID: "valid-provider"}
			err := authService.RegisterProvider(provider)
			assert.NoError(t, err)
		})
	})
}
