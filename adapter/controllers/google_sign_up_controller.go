package controllers

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"gorm.io/gorm"
	"net/http"
	"os"
	"sns-login/adapter/gateway"
	"sns-login/adapter/oidc"
	"sns-login/domain"
	"sns-login/usecase"
	"sns-login/usecase/interfaces"
)

type GoogleSignUpController struct {
	Interactor usecase.UserInteractor
}

func NewGoogleSignUpController(db *gorm.DB, logger interfaces.Logger) *GoogleSignUpController {
	return &GoogleSignUpController{
		Interactor: usecase.UserInteractor{
			UserRepository: &gateway.UserRepository{Db: db},
			Logger:         logger,
		},
	}
}

func (controller *GoogleSignUpController) AuthGoogleSignUp(w http.ResponseWriter, r *http.Request) {
	client := oidc.NewGoogleOidcClient()

	// CSRFを防ぐためにstateを保存し、後の処理でstateが一致するか確認する
	state, err := oidc.RandomState()
	if err != nil {
		controller.Interactor.Logger.Log(err)
		return
	}
	cookie := http.Cookie{Name: "state", Value: state}
	http.SetCookie(w, &cookie)

	// ユーザーをGoogleのログイン画面にリダイレクト
	redirectUrl := client.AuthUrl(
		"code",
		[]string{"openid", "email", "profile"},
		fmt.Sprintf(
			"%s://%s:%s/auth/google/sign_up/callback",
			os.Getenv("SERVER_PROTO"),
			os.Getenv("SERVER_HOST"),
			os.Getenv("SERVER_PORT"),
		),
		state,
	)
	http.Redirect(w, r, redirectUrl, 301)
}

func (controller *GoogleSignUpController) AuthGoogleSignUpCallback(w http.ResponseWriter, r *http.Request) {
	// 認可リクエストを送る前に設定したstateと一致するかを確認してCSRF攻撃を防ぐ
	cookieState, err := r.Cookie("state")
	if err != nil {
		controller.Interactor.Logger.Log(err)
		return
	}
	queryState := r.URL.Query().Get("state")
	if queryState != cookieState.Value {
		err = fmt.Errorf("state does not match %s : %s", queryState, cookieState.Value)
		controller.Interactor.Logger.Log(err)
		return
	}

	// 認可コードを取り出しトークンエンドポイントに投げることでid_tokenを取得できる
	client := oidc.NewGoogleOidcClient()
	tokenResp, err := client.PostTokenEndpoint(
		r.URL.Query().Get("code"),
		fmt.Sprintf(
			"%s://%s:%s/auth/google/sign_up/callback",
			os.Getenv("SERVER_PROTO"),
			os.Getenv("SERVER_HOST"),
			os.Getenv("SERVER_PORT"),
		),
		"authorization_code",
	)
	if err != nil {
		controller.Interactor.Logger.Log(err)
		return
	}

	// JWKsエンドポイントから公開鍵を取得しid_token(JWT)の署名を検証。改竄されていないことを確認する
	idToken, err := oidc.NewIdToken(tokenResp.IdToken)
	if err != nil {
		controller.Interactor.Logger.Log(err)
		return
	}
	if err := idToken.ValidateSignature(client.JwksEndpoint); err != nil {
		controller.Interactor.Logger.Log(err)
		return
	}

	// id_tokenのpayload部分をチェックし、期限切れなどしていないか確認する
	bytePayload, err := jwt.DecodeSegment(idToken.RawPayload)
	if err != nil {
		controller.Interactor.Logger.Log(err)
		return
	}
	payload := &oidc.GoogleIdTokenPayload{}
	if err := json.Unmarshal(bytePayload, payload); err != nil {
		controller.Interactor.Logger.Log(err)
		return
	}
	if err = payload.IsValid(client.ClientId); err != nil {
		controller.Interactor.Logger.Log(err)
		return
	}

	user := domain.User{
		Email:      payload.Email,
		Sub:        payload.Sub,
		IdProvider: payload.Iss,
	}
	if _, err := controller.Interactor.SignUp(user); err != nil {
		controller.Interactor.Logger.Log(err)
		return
	}
}
