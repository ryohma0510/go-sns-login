package handler

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestIndexHandler(t *testing.T) {
	if err := os.Chdir("../"); err != nil {
		panic(err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	IndexHandler(w, r)

	resp := w.Result()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
