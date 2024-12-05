package mockoidc

import (
	"log"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/lestrrat-go/jwx/v3/jwt/openid"
)

var (
	testAudience = "test-audience"
	testKeyID    = "test-key"
)

func (mockServer *OIDCMockServer) GenerateTestToken(customClaims map[string]interface{}) (string, error) {
	// Build JWT Token
	jwtBuilder := openid.NewBuilder()
	jwtBuilder.Issuer(mockServer.GetTestServer().URL)
	jwtBuilder.IssuedAt(time.Now())
	jwtBuilder.Expiration(time.Now().Add(30 * time.Minute))
	jwtBuilder.Claim(jwt.AudienceKey, testAudience)

	// Set Custom Claims
	for claimKey, claimValue := range customClaims {
		jwtBuilder.Claim(claimKey, claimValue)
	}

	jwtToken, err := jwtBuilder.Build()
	if err != nil {
		log.Printf("failed to building jwt token: %s", err)
		return "", err
	}

	jwkKey, err := jwk.Import(mockServer.PrivateKey)
	if err != nil {
		log.Printf("failed to building jwt token: %s", err)
		return "", err
	}

	jwkKey.Set(jwk.KeyIDKey, testKeyID)
	jwkKey.Set(jwk.AlgorithmKey, jwa.RS256())

	// Singed Key
	signed, err := jwt.Sign(jwtToken, jwt.WithKey(jwa.RS256(), jwkKey))
	if err != nil {
		log.Printf("failed to sign token: %s", err)
		return "", err
	}

	// Return token
	return string(signed), nil
}
