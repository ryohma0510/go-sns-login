package gateway

import (
	"gorm.io/gorm"
	"sns-login/domain"
)

type (
	UserRepository struct {
		Db *gorm.DB
	}

	User struct {
		gorm.Model
		Email      string
		Sub        string
		IdProvider string
	}
)

func (r *UserRepository) Create(du domain.User) (int, error) {
	user := &User{
		Email:      du.Email,
		Sub:        du.Sub,
		IdProvider: du.IdProvider,
	}
	if err := r.Db.Create(user).Error; err != nil {
		return 0, err
	}

	return int(user.ID), nil
}
