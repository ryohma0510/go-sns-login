package interfaces

import "sns-login/domain"

type UserRepository interface {
	Create(domain.User) (int, error)
}
