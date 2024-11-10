package keyset

import "github.com/lestrrat-go/jwx/jwk"

type KeysetDiscovery interface {
	GetKeyset() (jwk.Set, error)
}
