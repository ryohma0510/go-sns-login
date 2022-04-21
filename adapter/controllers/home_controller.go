package controllers

import (
	"html/template"
	"net/http"
	"sns-login/usecase"
	"sns-login/usecase/interfaces"
)

type HomeController struct {
	Interactor usecase.HomeInteractor
}

func NewHomeController(logger interfaces.Logger) *HomeController {
	return &HomeController{Interactor: usecase.HomeInteractor{Logger: logger}}
}

func (controller *HomeController) Index(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles("views/index.html")
	if err != nil {
		controller.Interactor.Logger.Log(err)
		return
	}
	if err := t.Execute(w, nil); err != nil {
		controller.Interactor.Logger.Log(err)
		return
	}
}
