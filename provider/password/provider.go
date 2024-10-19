package password

import "github.com/rekhansh/goauth"

type PasswordAuthProvider struct {
	*PasswordAuthProviderConfig
}

type PasswordAuthProviderConfig struct {
	goauth.AuthProviderConfig
}

func NewPasswordAuthProvider(config *PasswordAuthProviderConfig) (*PasswordAuthProvider, error) {
	if config == nil {
		config = &PasswordAuthProviderConfig{}
	}
	passwordAuthProvider := &PasswordAuthProvider{}
	return passwordAuthProvider, nil
}
