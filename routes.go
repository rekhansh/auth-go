package goauth

import "github.com/gorilla/mux"

func (a *AuthService) RegisterRoutes(r *mux.Router) {
	authSubRouter := r.PathPrefix(a.URLPrefix).Subrouter()

	for _, p := range a.providers {
		p.RegisterRoutes(authSubRouter)
	}
}
