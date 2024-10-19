package goauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToken(t *testing.T) {
	// Check Empty Token
	tokenStr := ""
	issuer := getUnverifiedIssuer(tokenStr)
	assert.Empty(t, issuer)

	// Check with Token
	tokenStr = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlJla2hhbnNoIiwiaWF0IjoxNTE2MjM5MDIyLCJpc3MiOiJ0ZXN0In0.RGurx6kQ7fNcwpqMqoXDs8Z6odBgF1NbKM-y6xBs61I"
	issuer = getUnverifiedIssuer(tokenStr)
	assert.Equal(t, issuer, "test")
}
