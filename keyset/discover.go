package keyset

import "github.com/lestrrat-go/jwx/v3/jwk"

type KeysetDiscovery interface {
	GetKeyset() (jwk.Set, error)
}
