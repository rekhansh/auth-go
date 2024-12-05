package oidcutils

const (
	OIDCEndpointWelKnownOpenIDConfiguration = "/.well-known/openid-configuration"
	OIDCEndpointAuthorization               = "/oauth2/v1/authorize"
	OIDCEndpointToken                       = "/oauth2/v1/token"
	OIDCEndpointUserInfo                    = "/oauth2/v1/userinfo"
	OIDCEndpointJwksUri                     = "/oauth2/v1/keys"
	OIDCEndpointRegistration                = "/oauth2/v1/clients"
)

type OpenIDConfig struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserInfoEndpoint                 string   `json:"userinfo_endpoint"`
	Registration                     string   `json:"registration_endpoint"`
	JwksURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IdTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}
