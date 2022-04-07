package main

import (
	"fmt"
	"github.com/joho/godotenv"
	"net/http"
	"os"
	"sns-login/handler"
)

func main() {
	loadEnv()

	http.HandleFunc("/", handler.IndexHandler)
	http.HandleFunc("/auth/google", handler.AuthGoogleHandler)
	http.HandleFunc("/auth/google/callback", handler.AuthGoogleCallbackHandler)
	if err := http.ListenAndServe(fmt.Sprintf(":%s", os.Getenv("SERVER_PORT")), nil); err != nil {
		fmt.Println(err)
	}
}

func loadEnv() {
	err := godotenv.Load(".env")

	if err != nil {
		fmt.Printf("読み込み出来ませんでした: %v", err)
	}
}
