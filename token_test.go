package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToken(t *testing.T) {
	// Check Empty Token
	tokenStr := ""
	token, err := getUnverifiedToken(tokenStr)
	assert.NotNil(t, err)
	assert.Nil(t, token)

	// Check with Token
	tokenStr = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlJla2hhbnNoIiwiaWF0IjoxNTE2MjM5MDIyLCJpc3MiOiJ0ZXN0In0.RGurx6kQ7fNcwpqMqoXDs8Z6odBgF1NbKM-y6xBs61I"
	token, err = getUnverifiedToken(tokenStr)
	assert.Nil(t, err)
	assert.NotNil(t, token)
	issuer, _ := token.Issuer()
	assert.Equal(t, issuer, "test")
}
