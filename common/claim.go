package common

import (
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type AuthClaim struct {
	jwt.Token
}
