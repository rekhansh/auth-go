package goauth

type AuthService struct {
	*AuthServiceConfig
	providers []AuthProvider
}

type AuthServiceConfig struct {
	// Url Prefix for auth. Default is /auth
	URLPrefix string
}

func New(authConfig *AuthServiceConfig) *AuthService {
	if authConfig == nil {
		authConfig = &AuthServiceConfig{}
	}

	// Update Defaults
	if authConfig.URLPrefix == "" {
		authConfig.URLPrefix = DefaultURLPrefix
	}

	auth := &AuthService{
		AuthServiceConfig: authConfig,
	}
	return auth
}
