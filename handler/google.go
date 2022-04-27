package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sns-login/model"
	"sns-login/oidc"

	"github.com/dgrijalva/jwt-go"
	"gorm.io/gorm"
)

func AuthGoogleSignUpHandler(w http.ResponseWriter, r *http.Request) {
	client := oidc.NewGoogleOidcClient()

	// CSRFを防ぐためにstateを保存し、後の処理でstateが一致するか確認する
	state, err := oidc.RandomState()
	if err != nil {
		fmt.Println(err)
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

func AuthGoogleSignUpCallbackHandler(w http.ResponseWriter, r *http.Request, db *gorm.DB) {
	// 認可リクエストを送る前に設定したstateと一致するかを確認してCSRF攻撃を防ぐ
	cookieState, err := r.Cookie("state")
	if err != nil {
		fmt.Printf("Cookie get error %s", err)
		return
	}
	queryState := r.URL.Query().Get("state")
	if queryState != cookieState.Value {
		fmt.Printf("state does not match %s : %s", queryState, cookieState.Value)
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
		fmt.Println(err)
		return
	}

	// JWKsエンドポイントから公開鍵を取得しid_token(JWT)の署名を検証。改竄されていないことを確認する
	idToken, err := oidc.NewIdToken(tokenResp.IdToken)
	if err != nil {
		fmt.Println(err)
		return
	}
	if err := idToken.ValidateSignature(client.JwksEndpoint); err != nil {
		fmt.Println(err)
		return
	}

	// id_tokenのpayload部分をチェックし、期限切れなどしていないか確認する
	bytePayload, err := jwt.DecodeSegment(idToken.RawPayload)
	if err != nil {
		fmt.Println(err)
		return
	}
	payload := &oidc.GoogleIdTokenPayload{}
	if err := json.Unmarshal(bytePayload, payload); err != nil {
		fmt.Println(err)
		return
	}
	if err = payload.IsValid(client.ClientId); err != nil {
		fmt.Println(err)
		return
	}

	idProvider, err := oidc.IssToIdProvider(payload.Iss)
	if err != nil {
		fmt.Println(err)
		return
	}
	user := &model.User{Email: payload.Email, Sub: payload.Sub, IdProvider: idProvider}
	db.Create(user)
	fmt.Printf("success to create user :%v", user)
}
