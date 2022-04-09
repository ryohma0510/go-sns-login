package oidc

import (
	"errors"
	"time"
)

type GoogleIdTokenPayload struct {
	Iss           string `json:"iss"`
	Azp           string `json:"azp"`
	Aud           string `json:"aud"`
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	AtHash        string `json:"at_hash"`
	Nonce         string `json:"nonce"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Locale        string `json:"locale"`
	Iat           int64  `json:"iat"`
	Exp           int64  `json:"exp"`
}

func (c oidcClient) ValidateIdTokenPayload(iss string, aud string, exp int64) error {
	if c.issuer != iss {
		return errors.New("token issuer mismatch")
	}

	if c.clientId != aud {
		return errors.New("token audience mismatch")
	}

	if (time.Now().Unix() - exp) > 0 {
		return errors.New("token expired")
	}

	return nil
}
