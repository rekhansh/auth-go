package main

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/rekhansh/goauth"
	"github.com/rekhansh/goauth/provider/jwt"
	"github.com/rekhansh/goauth/provider/oidc"
)

var authService *goauth.AuthService

func initAuthService(pathPrefix string) error {
	authService = goauth.New(&goauth.AuthServiceConfig{
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

func main() {
	// register auth routers to server
	router := mux.NewRouter()

	// Auth
	initAuthService("/auth")
	authService.RegisterRoutes(router)

	// Other Requests
	// Without Auth
	router.HandleFunc("/ping", PingHandler)

	// With Auth without middleware
	router.HandleFunc("/api/v1/userinfo", GetUserInfoWithAuthCheckHandler)

	// With Auth with Middleware
	subRoute := router.PathPrefix("/api/v1").Subrouter()
	subRoute.Use(authService.AuthMiddleware)
	subRoute.HandleFunc("/user", GetUserInfoWithoutAuthCheckHandler)
	subRoute.HandleFunc("/test", GetAuthenicatedResponseHandler)

	// Serve
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

func GetUserInfoWithAuthCheckHandler(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"message": "with auth check",
	}

	// Check Auth - TODO
	// token, err := authService.ValidateToken("")

	// Encode the response as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func GetUserInfoWithoutAuthCheckHandler(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"message": "wihtout auth check",
	}

	//

	// Encode the response as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func GetAuthenicatedResponseHandler(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"message": "test",
	}

	// Encode the response as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
