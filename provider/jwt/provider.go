package jwt

import "github.com/lestrrat-go/jwx/v3/jwt"

type JwtAuthProvider struct {
	*JwtAuthProviderConfig
}

type JwtAuthProviderConfig struct {
	ID     string
	Issuer string
}

func NewJwtAuthProvider(config *JwtAuthProviderConfig) (*JwtAuthProvider, error) {
	if config == nil {
		config = &JwtAuthProviderConfig{}
	}
	if config.Issuer == "" {
		config.Issuer = "jwt"
	}
	jwtAuthProvider := &JwtAuthProvider{
		JwtAuthProviderConfig: config,
	}
	return jwtAuthProvider, nil
}

func (j *JwtAuthProviderConfig) GetID() string {
	if j.ID != "" {
		return j.ID
	}
	return j.Issuer
}

func (j *JwtAuthProviderConfig) IsTokenSupported(token jwt.Token) bool {
	return false
}
