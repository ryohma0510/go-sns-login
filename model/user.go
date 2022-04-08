package model

import (
	"database/sql"
)

type User struct {
	Db         *sql.DB
	Id         int64
	Email      string
	Sub        string
	IdProvider string
}

func CreateUserTable(db *sql.DB) error {
	// 本来はsub, id_providerにmultiple unique indexを貼るべきだが割愛
	const sql = `
 CREATE TABLE IF NOT EXISTS users (
 	id   INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
 	email TEXT NOT NULL UNIQUE,
	sub TEXT NOT NULL UNIQUE,
	id_provider TEXT NOT NULL 
 );
 `
	if _, err := db.Exec(sql); err != nil {
		return err
	}

	return nil
}

func (user *User) Create(db *sql.DB) error {
	const sql = "INSERT INTO users(email,sub,id_provider) VALUES (?, ?, ?);"
	r, err := db.Exec(sql, user.Email, user.Sub, user.IdProvider)
	if err != nil {
		return err
	}

	id, err := r.LastInsertId()
	if err != nil {
		return err
	}
	user.Id = id

	return nil
}
