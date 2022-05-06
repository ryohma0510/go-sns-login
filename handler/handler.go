package handler

import (
	"html/template"
	"net/http"
)

func IndexHandler(w http.ResponseWriter, _ *http.Request) {
	t, err := template.ParseFiles("views/index.html")
	if err != nil {
		panic(err.Error())
	}
	if err := t.Execute(w, nil); err != nil {
		panic(err.Error())
	}
}
