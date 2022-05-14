package oidc

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestClientSecret_String(t *testing.T) {
	c := client{clientSecret: clientSecret("super-secret-value")}
	assert.Equal(t, fmt.Sprint(c.clientSecret), secretMaskingStr)
}

func TestClientSecret_GoString(t *testing.T) {
	c := client{clientSecret: clientSecret("super-secret-value")}
	assert.Equal(t, fmt.Sprintf("%#v", c.clientSecret), secretMaskingStr)
}
