package model

import (
	"gorm.io/gorm"
)

//go:generate stringer -type=IdProvider
type IdProvider int

const (
	Google IdProvider = iota + 1
)

type User struct {
	gorm.Model
	Id         int64
	Email      string
	Sub        string
	IdProvider IdProvider
}
