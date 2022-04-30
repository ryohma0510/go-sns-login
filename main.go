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
	"sns-login/logger"
	"sns-login/model"
)

func main() {
	l := logger.New(false)
	if err := loadEnv(); err != nil {
		l.Logger.Error().Err(err)
	}

	db, err := gorm.Open(sqlite.Open("./database.db"), &gorm.Config{})
	if err != nil {
		l.Logger.Error().Err(err)
		return
	}
	if err := initDb(db); err != nil {
		l.Logger.Error().Err(err)
		return
	}

	router := mux.NewRouter()
	router.HandleFunc("/", handler.IndexHandler)
	// ユーザーをGoogleのログイン画面にリダイレクトする
	router.HandleFunc("/auth/google/sign_up", handler.AuthGoogleSignUpHandler)
	// Googleのログイン画面からリダイレクトされ戻ってくるときのエンドポイント
	router.HandleFunc("/auth/google/sign_up/callback", func(w http.ResponseWriter, r *http.Request) {
		handler.AuthGoogleSignUpCallbackHandler(w, r, db)
	}).Methods("GET")

	server := http.Server{
		Handler: router,
		Addr:    fmt.Sprintf("%s:%s", os.Getenv("SERVER_HOST"), os.Getenv("SERVER_PORT")),
	}
	if err := server.ListenAndServe(); err != nil {
		l.Logger.Error().Err(err)
	}
}

// client_idは知られても問題ないが、client_secretは秘匿する必要がある
func loadEnv() error {
	err := godotenv.Load(".env")

	if err != nil {
		return err
	}

	return nil
}

func initDb(db *gorm.DB) error {
	if err := db.AutoMigrate(&model.User{}); err != nil {
		return err
	}

	return nil
}
