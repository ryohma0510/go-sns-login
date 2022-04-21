package controllers

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"os"
	"sns-login/usecase"
	"testing"
)

func TestIndexHandler(t *testing.T) {
	if err := os.Chdir("../"); err != nil {
		panic(err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	controller := HomeController{Interactor: usecase.HomeInteractor{Logger: mockLogger{}}}
	controller.Index(w, r)

	resp := w.Result()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
