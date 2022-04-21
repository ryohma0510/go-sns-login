package router

import (
	"github.com/gorilla/mux"
	"sns-login/adapter/controllers"
	"sns-login/external"
	"sns-login/external/sqlite"
)

func Router() *mux.Router {
	router := mux.NewRouter()

	db := sqlite.Connect()
	logger := &external.Logger{}
	homeController := controllers.NewHomeController(logger)
	googleSignUpController := controllers.NewGoogleSignUpController(db, logger)

	router.HandleFunc("/", homeController.Index)
	// ユーザーをGoogleのログイン画面にリダイレクトする
	router.HandleFunc("/auth/google/sign_up", googleSignUpController.AuthGoogleSignUp)
	// Googleのログイン画面からリダイレクトされ戻ってくるときのエンドポイント
	router.HandleFunc("/auth/google/sign_up/callback", googleSignUpController.AuthGoogleSignUpCallback).Methods("GET")

	return router
}
