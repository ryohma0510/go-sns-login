package main

import (
	"fmt"
	"net/http"
	"os"
	"sns-login/external"
	myRouter "sns-login/external/router"
	"sns-login/external/sqlite"
)

func main() {
	external.LoadEnv()

	db := sqlite.Connect()
	sqlite.MigrateAll(db)

	router := myRouter.Router()

	server := http.Server{
		Handler: router,
		Addr:    fmt.Sprintf("%s:%s", os.Getenv("SERVER_HOST"), os.Getenv("SERVER_PORT")),
	}
	if err := server.ListenAndServe(); err != nil {
		fmt.Println(err)
	}
}
