package okta

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/rekhansh/goauth/config"
)

func (o *OktaAuthProvider) ValidateAuthToken(tokenString string) (jwt.Token, error) {
	// Get KeySet
	keyset, err := o.getKeySet()
	if err != nil {
		return nil, err
	}

	// jwt
	validator := jwt.ValidatorFunc(func(_ context.Context, t jwt.Token) error {
		// if time.Now().Month() != 8 {
		// 	return fmt.Errorf(`tokens are only valid during August!`)
		// }
		return nil
	})

	// Get Token
	token, err := jwt.Parse(
		[]byte(tokenString),
		jwt.WithKeySet(keyset),
		jwt.WithIssuer(o.Issuer),
		jwt.WithValidator(validator),
	)
	if err != nil {
		fmt.Printf("failed to parse payload: %s\n", err)
	}

	return token, nil
}

func (o *OktaAuthProvider) getKeySet() (jwk.Set, error) {
	// TODO -- Cache

	// Get Url
	keysetUrl, err := o.fetchKeysetUrl()
	if err != nil {
		return nil, err
	}

	// getkeyset
	keyset, err := jwk.Fetch(context.Background(), keysetUrl)
	if err != nil {
		return nil, err
	}

	// return keyset
	return keyset, nil
}

func (o *OktaAuthProvider) fetchKeysetUrl() (string, error) {
	metadataUrl := o.Issuer + wellKnownUrlPath
	resp, err := http.Get(metadataUrl)
	if err != nil {
		return "", fmt.Errorf("failed to fetch metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	var openidconfig config.OpenIDConfig

	if err := json.Unmarshal(body, &openidconfig); err != nil {
		return "", fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	if openidconfig.JwksURI == "" {
		return "", fmt.Errorf("keyset url not found")
	}

	return openidconfig.JwksURI, nil
}
