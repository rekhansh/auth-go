package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/rekhansh/auth"
	"github.com/rekhansh/auth/provider/core/jwt"
	"github.com/rekhansh/auth/provider/core/oidc"
)

var authService *auth.AuthService

func initAuthService(pathPrefix string) error {
	authService = auth.New(&auth.AuthServiceConfig{
		URLPrefix: pathPrefix,
	})

	// setup providers
	registerJwtProvider()
	registerOidcProvider()
	return nil
}

func registerJwtProvider() error {
	provider, err := jwt.NewJwtAuthProvider(nil)
	if err != nil {
		return err
	}
	authService.RegisterProvider(provider)
	return nil
}

func registerOidcProvider() error {
	provider, err := oidc.NewOidcProvider(nil)
	if err != nil {
		return err
	}
	authService.RegisterProvider(provider)
	return nil
}

func setupRouter() *mux.Router {
	// register auth routers to server
	router := mux.NewRouter()

	// Auth
	initAuthService("/auth")
	authService.RegisterRoutes(router)

	// 2. Ping Endpoint
	router.HandleFunc("/ping", PingHandler)

	// 3. Public Endpoint
	router.HandleFunc("/api/v1/public", PingHandler)

	// 4. Private Endpoint
	// 4.1 Private Endpoint using Middleware
	subRoute := router.PathPrefix("/api/v1/private").Subrouter()
	subRoute.Use(authService.AuthMiddleware)
	subRoute.HandleFunc("/user-with-middleware", GetUserInfoHandler)
	subRoute.HandleFunc("/test", GetUserInfoHandler)

	// 4.2 Private Endpoint without Middleware
	router.HandleFunc("/api/v1/private/user-without-middleware", GetUserInfoHandler)

	return router
}

func main() {
	// Serve
	router := setupRouter()
	http.ListenAndServe(":80", router)
}

func PingHandler(w http.ResponseWriter, r *http.Request) {
	// Create the response
	response := map[string]string{
		"message": "ping successful",
	}

	// Encode the response as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func GetUserInfoHandler(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"message": "user info",
	}

	tokenStr := ""
	tokenHeader := r.Header.Get("Authorization")
	splitToken := strings.Split(tokenHeader, " ")
	if len(splitToken) == 2 {
		tokenStr = splitToken[1]
	}
	if tokenStr == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "missing token",
		})
	}
	token, err := authService.ValidateToken(tokenStr)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "invalid token",
		})
		return
	}

	response["token"] = token

	// Encode the response as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
