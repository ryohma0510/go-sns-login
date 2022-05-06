package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sns-login/logger"
	"sns-login/model"
	"sns-login/oidc"

	"github.com/dgrijalva/jwt-go"
	"gorm.io/gorm"
)

func AuthGoogleSignUpHandler(w http.ResponseWriter, r *http.Request) {
	l := logger.New(false)
	client := oidc.NewGoogleOidcClient()

	// CSRFを防ぐためにstateを保存し、後の処理でstateが一致するか確認する
	state, err := oidc.RandomState()
	if err != nil {
		l.Logger.Error().Err(err)
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

func AuthGoogleSignUpCallbackHandler(_ http.ResponseWriter, r *http.Request, db *gorm.DB) {
	l := logger.New(false)

	// 認可リクエストを送る前に設定したstateと一致するかを確認してCSRF攻撃を防ぐ
	cookieState, err := r.Cookie("state")
	if err != nil {
		l.Logger.Error().Err(err)
		return
	}
	queryState := r.URL.Query().Get("state")
	if queryState != cookieState.Value {
		err = fmt.Errorf("state parameter does not match for query: %s, cookie: %s", queryState, cookieState)
		l.Logger.Error().Err(err)
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
		l.Logger.Error().Err(err)
		return
	}

	// JWKsエンドポイントから公開鍵を取得しid_token(JWT)の署名を検証。改竄されていないことを確認する
	idToken, err := oidc.NewIdToken(tokenResp.IdToken)
	if err != nil {
		l.Logger.Error().Err(err)
		return
	}
	if err := idToken.ValidateSignature(client.JwksEndpoint); err != nil {
		l.Logger.Error().Err(err)
		return
	}

	// id_tokenのpayload部分をチェックし、期限切れなどしていないか確認する
	bytePayload, err := jwt.DecodeSegment(idToken.RawPayload)
	if err != nil {
		l.Logger.Error().Err(err)
		return
	}
	payload := &oidc.GoogleIdTokenPayload{}
	if err := json.Unmarshal(bytePayload, payload); err != nil {
		l.Logger.Error().Err(err)
		return
	}
	if err = payload.IsValid(client.ClientId); err != nil {
		l.Logger.Error().Err(err)
		return
	}

	idProvider, err := oidc.IssToIdProvider(payload.Iss)
	if err != nil {
		l.Logger.Error().Err(err)
		return
	}
	user := &model.User{Email: payload.Email, Sub: payload.Sub, IdProvider: idProvider}
	db.Create(user)
	l.Logger.Info().Msg("success to create user")
}
