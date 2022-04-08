package handler

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"os"
	"sns-login/model"
	"sns-login/oidc"
	"strings"
)

func AuthGoogleSignUpHandler(w http.ResponseWriter, r *http.Request) {
	client := oidc.NewGoogleOidcClient()

	state, err := oidc.RandomState()
	if err != nil {
		fmt.Println(err)
		return
	}
	cookie := http.Cookie{Name: "state", Value: state}
	http.SetCookie(w, &cookie)

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

func AuthGoogleSignUpCallbackHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
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

	// id_tokenはトークンエンドポイントから受け取った直後でIdProviderから受け取っていることが保障されているので署名の検証をしない
	base64EncPayload := strings.Split(tokenResp.IdToken, ".")[1]
	bytePayload, err := jwt.DecodeSegment(base64EncPayload)
	if err != nil {
		fmt.Println(err)
		return
	}

	googleIdToken := &oidc.GoogleIdToken{}
	if err := json.Unmarshal(bytePayload, googleIdToken); err != nil {
		fmt.Println(err)
		return
	}

	user := model.User{Email: googleIdToken.Email, Sub: googleIdToken.Sub, IdProvider: googleIdToken.Iss}
	if err = user.Create(db); err != nil {
		fmt.Println(err)
		return
	}
}
