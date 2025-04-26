package auth

const (
	DefaultURLPrefix = "/auth"
)

type AuthService struct {
	*AuthServiceConfig
	providers map[string]AuthProvider
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
		providers:         make(map[string]AuthProvider),
	}
	return auth
}
