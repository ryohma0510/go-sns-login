package controllers

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"sns-login/domain"
	"sns-login/usecase"
	"testing"
)

type mockLogger struct{}

func (logger mockLogger) Log(args ...interface{}) {}

type mockUserRepository struct{}

func (repository mockUserRepository) Create(user domain.User) (int, error) {
	return 0, nil
}

func TestAuthGoogleSignUp(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/google/sign_up", nil)
	controller := &GoogleSignUpController{Interactor: usecase.UserInteractor{
		UserRepository: mockUserRepository{},
		Logger:         mockLogger{},
	}}
	controller.AuthGoogleSignUp(w, r)

	resp := w.Result()
	assert.Equal(t, http.StatusMovedPermanently, resp.StatusCode)
}
