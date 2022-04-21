package oidc

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestNewIdToken(t *testing.T) {
	patterns := []struct {
		desc          string
		isExpectValid bool
		header        string
		payload       string
		signature     string
	}{
		{
			"valid",
			true,
			`{
  "alg": "RS256",
  "kid": "8462a71da4f6d611fc0fecf0fc4ba9c37d65e6cd",
  "typ": "JWT"
}`,
			"dummy",
			"dummy",
		},
		{
			"invalid header",
			false,
			"invalid header",
			"dummy",
			"dummy",
		},
	}

	for _, pattern := range patterns {
		b64Header := base64.StdEncoding.EncodeToString([]byte(pattern.header))
		b64Payload := base64.StdEncoding.EncodeToString([]byte(pattern.payload))
		b64Sig := base64.StdEncoding.EncodeToString([]byte(pattern.signature))

		b64Token := strings.Join([]string{b64Header, b64Payload, b64Sig}, ".")

		_, err := NewIdToken(b64Token)
		isActualValid := err == nil

		if pattern.isExpectValid != isActualValid {
			t.Errorf(
				"pattern %s: want %t, actual %t, err: %s",
				pattern.desc,
				pattern.isExpectValid,
				isActualValid,
				err,
			)
		}
	}
}
