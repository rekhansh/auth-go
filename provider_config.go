package goauth

import "github.com/gorilla/mux"

type AuthProviderConfig struct {
	Issuer string
}

func (p *AuthProviderConfig) GetIssuer() string {
	return p.Issuer
}

func (p *AuthProviderConfig) RegisterRoutes(r *mux.Router) {}
