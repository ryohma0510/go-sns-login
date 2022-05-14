package model

import (
	"gorm.io/gorm"
)

//go:generate stringer -type=IdProvider
type idProvider int

const (
	Google idProvider = iota + 1
	Yahoo
)

type User struct {
	gorm.Model
	Id         int64
	Email      string
	Sub        string
	IdProvider idProvider
}
