package keyset

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/lestrrat-go/jwx/v3/jwk"
	oidcutils "github.com/rekhansh/auth/utils/oidc"
)

const (
	ErrorEmptyBaseUrl          = "base url is empty"
	ErrorFailedToFetchMetadata = "failed to fetch metadata:"
	ErrorUnexpectedStatusCode  = "unexpected status code:"
	ErrorFailedToReadBody      = "failed to read response body:"
	ErrorFailedToUnmarshal     = "failed to unmarshal metadata:"
	ErrorKeysetUrlEmpty        = "keyset url empy"
	ErrorFailedToFetchKeyset   = "failed to fetch keyset:"
)

type OidcKeysetDiscovery struct {
	BaseUrl string
}

func (o *OidcKeysetDiscovery) GetKeyset() (jwk.Set, error) {
	if o.BaseUrl == "" {
		return nil, errors.New(ErrorEmptyBaseUrl)
	}

	// Get Metadata
	metadataUrl := o.BaseUrl + oidcutils.OIDCEndpointWelKnownOpenIDConfiguration
	resp, err := http.Get(metadataUrl)
	if err != nil {
		return nil, fmt.Errorf(ErrorFailedToFetchMetadata+" %v", err)
	}
	defer resp.Body.Close()

	// response status code check
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(ErrorUnexpectedStatusCode+" %v", resp.StatusCode)
	}

	// read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf(ErrorFailedToReadBody+" %v", err)
	}

	// unmarshal response body
	var openidconfig oidcutils.OpenIDConfig

	if err := json.Unmarshal(body, &openidconfig); err != nil {
		return nil, fmt.Errorf(ErrorFailedToUnmarshal+" %v", err)
	}

	if openidconfig.JwksURI == "" {
		return nil, errors.New(ErrorKeysetUrlEmpty)
	}

	// getkeyset
	keyset, err := jwk.Fetch(context.Background(), openidconfig.JwksURI)
	if err != nil {
		return nil, fmt.Errorf(ErrorFailedToFetchKeyset+" %v", err)
	}

	// return keyset
	return keyset, nil
}
