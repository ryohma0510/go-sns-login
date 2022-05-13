package oidc

import (
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
	"time"
)

func TestGoogleIdTokenPayload_IsValid(t *testing.T) {
	validClientId := os.Getenv("GOOGLE_CLIENT_ID") // TODO: ちゃんとしたい

	patterns := []struct {
		desc     string
		expected bool
		clientId string
		iss      string
		aud      string
		exp      int64
	}{
		{
			"valid",
			true,
			validClientId,
			"https://accounts.google.com",
			validClientId,
			time.Now().AddDate(0, 0, 1).Unix(),
		},
		{
			"invalid iss",
			false,
			validClientId,
			"https://accounts.google.coms",
			validClientId,
			time.Now().AddDate(0, 0, 1).Unix(),
		},
		{
			"invalid aud",
			false,
			validClientId,
			"https://accounts.google.coms",
			"invalid aud",
			time.Now().AddDate(0, 0, 1).Unix(),
		},
		{
			"invalid exp",
			false,
			validClientId,
			"https://accounts.google.coms",
			validClientId,
			time.Now().AddDate(0, 0, -1).Unix(),
		},
	}

	for _, pattern := range patterns {
		payload := googleIdTokenPayload{
			Iss: pattern.iss,
			Aud: pattern.aud,
			Exp: pattern.exp,
		}

		err := payload.validate(pattern.clientId)
		actual := err == nil

		assert.Equal(t, pattern.expected, actual)
	}
}
