package main

import (
	"fmt"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"net/http"
	"os"
	"sns-login/handler"
	"sns-login/model"
)

func main() {
	loadEnv()

	db, err := gorm.Open(sqlite.Open("./database.db"), &gorm.Config{})
	if err != nil {
		fmt.Printf("DB Connection error: %s", err)
		return
	}
	if err := initDb(db); err != nil {
		fmt.Println(err)
		return
	}

	router := mux.NewRouter()
	router.HandleFunc("/", handler.IndexHandler)
	router.HandleFunc("/auth/google/sign_up", handler.AuthGoogleSignUpHandler)
	router.HandleFunc("/auth/google/sign_up/callback", func(w http.ResponseWriter, r *http.Request) {
		handler.AuthGoogleSignUpCallbackHandler(w, r, db)
	}).Methods("GET")

	server := http.Server{
		Handler: router,
		Addr:    fmt.Sprintf("%s:%s", os.Getenv("SERVER_HOST"), os.Getenv("SERVER_PORT")),
	}
	if err := server.ListenAndServe(); err != nil {
		fmt.Println(err)
	}
}

func loadEnv() {
	err := godotenv.Load(".env")

	if err != nil {
		fmt.Printf("読み込み出来ませんでした: %v", err)
	}
}

func initDb(db *gorm.DB) error {
	if err := db.AutoMigrate(&model.User{}); err != nil {
		return err
	}

	return nil
}
