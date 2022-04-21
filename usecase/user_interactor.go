package usecase

import (
	"sns-login/domain"
	"sns-login/usecase/interfaces"
)

type UserInteractor struct {
	UserRepository interfaces.UserRepository
	Logger         interfaces.Logger
}

func (i *UserInteractor) SignUp(u domain.User) (int, error) {
	i.Logger.Log("store user!")
	return i.UserRepository.Create(u)
}
