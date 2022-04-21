package sqlite

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"sns-login/domain"
)

func Connect() *gorm.DB {
	db, err := gorm.Open(sqlite.Open("./database.db"), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	return db
}

func MigrateAll(db *gorm.DB) {
	if err := db.AutoMigrate(&domain.User{}); err != nil {
		panic(err)
	}
}
