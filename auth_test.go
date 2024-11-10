package auth

import (
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

func TestAuthService(t *testing.T) {
	// register auth routers to server
	router := mux.NewRouter()
	authService := New(&AuthServiceConfig{})
	assert.NotNil(t, authService)
	server := httptest.NewServer(router)
	defer server.Close()
}
