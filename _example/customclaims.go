package main

import "github.com/rekhansh/auth/common"

type customClaims common.AuthClaim

func (c *customClaims) GetMyClaim() string {
	// Some Custom Logic
	var myclaim string
	err := c.Get("myclaim", myclaim)
	if err != nil {
		// Handle Error
	}
	return myclaim
}
