package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/rekhansh/auth/common"
)

const (
	AuthClaimContextKey = "authClaim"
)

// AuthMiddleware
func (a *AuthService) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := extractToken(r)
		if tokenString == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"message": "missing token",
			})
			return
		}

		// Validate the token
		authClaim, err := a.ValidateToken(tokenString)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"message": "invalid token",
			})
			return
		}

		// Store the auth claim in the request context
		ctx := r.Context()
		ctx = context.WithValue(ctx, AuthClaimContextKey, authClaim)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

// Extract token from the Authorization header
func extractToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	// Authorization: Bearer <token>
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 {
		return ""
	}

	return parts[1]
}

func GetAuthClaimFromContext(ctx context.Context) (*common.AuthClaim, bool) {
	authClaim, ok := ctx.Value(AuthClaimContextKey).(*common.AuthClaim)
	return authClaim, ok
}
