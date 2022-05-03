package oidc

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestClientSecret(t *testing.T) {
	c := oidcClient{clientSecret: clientSecret("super-secret-value")}
	assert.Equal(t, fmt.Sprint(c.clientSecret), secretMaskingStr)
}
