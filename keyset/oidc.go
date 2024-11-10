package keyset

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/rekhansh/auth/config"
)

type OidcKeysetDiscovery struct {
	BaseUrl string
}

const (
	wellKnownUrlPath = "/.well-known/openid-configuration"
)

func (o *OidcKeysetDiscovery) GetKeyset() (jwk.Set, error) {
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

func (o *OidcKeysetDiscovery) fetchKeysetUrl() (string, error) {
	metadataUrl := o.BaseUrl + wellKnownUrlPath
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
