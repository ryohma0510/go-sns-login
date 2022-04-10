package handler

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthGoogleSignUpHandler(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/google/sign_up", nil)
	AuthGoogleSignUpHandler(w, r)

	resp := w.Result()
	assert.Equal(t, http.StatusMovedPermanently, resp.StatusCode)
}
