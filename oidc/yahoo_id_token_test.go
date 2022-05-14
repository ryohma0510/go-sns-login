package oidc

import (
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
	"time"
)

func TestYahooIdTokenPayload_IsValid(t *testing.T) {
	validClientId := os.Getenv("YAHOO_CLIENT_ID") // TODO: ちゃんとしたい

	patterns := []struct {
		desc     string
		expected error
		clientId string
		iss      string
		aud      string
		exp      int64
	}{
		{
			"valid",
			nil,
			validClientId,
			"https://auth.login.yahoo.co.jp/yconnect/v2",
			validClientId,
			time.Now().AddDate(0, 0, 1).Unix(),
		},
		{
			"invalid iss",
			errIssMismatch,
			validClientId,
			"https://accounts.yahoo.coms",
			validClientId,
			time.Now().AddDate(0, 0, 1).Unix(),
		},
		{
			"invalid aud",
			errAudMismatch,
			validClientId,
			"https://auth.login.yahoo.co.jp/yconnect/v2",
			"invalid aud",
			time.Now().AddDate(0, 0, 1).Unix(),
		},
		{
			"invalid exp",
			errIdTokenExpired,
			validClientId,
			"https://auth.login.yahoo.co.jp/yconnect/v2",
			validClientId,
			time.Now().AddDate(0, 0, -1).Unix(),
		},
	}

	for _, pattern := range patterns {
		payload := yahooIdTokenPayload{
			Iss: pattern.iss,
			Aud: []string{pattern.aud},
			Exp: pattern.exp,
		}

		actual := payload.validate(pattern.clientId)

		assert.Equal(t, pattern.expected, actual)
	}
}
