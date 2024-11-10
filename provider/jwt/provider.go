package jwt

type JwtAuthProvider struct {
	*JwtAuthProviderConfig
}

type JwtAuthProviderConfig struct {
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

func (j *JwtAuthProvider) GetIssuer() string {
	return j.Issuer
}
