package oidc

import (
	"encoding/base64"
	"github.com/stretchr/testify/assert"
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
		provider      IdProvider
	}{
		{
			"valid",
			true,
			`{
  "alg": "RS256",
  "kid": "8462a71da4f6d611fc0fecf0fc4ba9c37d65e6cd",
  "typ": "JWT"
}`,
			"{}",
			"{}",
			Google,
		},
		{
			"valid",
			true,
			`{
  "alg": "RS256",
  "kid": "8462a71da4f6d611fc0fecf0fc4ba9c37d65e6cd",
  "typ": "JWT"
}`,
			"{}",
			"{}",
			Yahoo,
		},
		{
			"invalid header",
			false,
			"invalid header",
			"{}",
			"{}",
			Google,
		},
	}

	for _, pattern := range patterns {
		b64Header := base64.StdEncoding.EncodeToString([]byte(pattern.header))
		b64Payload := base64.StdEncoding.EncodeToString([]byte(pattern.payload))
		b64Sig := base64.StdEncoding.EncodeToString([]byte(pattern.signature))

		b64Token := strings.Join([]string{b64Header, b64Payload, b64Sig}, ".")

		_, err := NewIdToken(b64Token, pattern.provider)

		if pattern.isExpectValid {
			assert.Nil(t, err)
		} else {
			assert.Error(t, err)
		}
	}
}
