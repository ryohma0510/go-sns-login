package oidc

import (
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
		payload := GoogleIdTokenPayload{
			Iss: pattern.iss,
			Aud: pattern.aud,
			Exp: pattern.exp,
		}

		err := payload.IsValid(pattern.clientId)
		actual := err == nil

		if pattern.expected != actual {
			t.Errorf("pattern %s: want %t, actual %t", pattern.desc, pattern.expected, actual)
		}
	}
}
