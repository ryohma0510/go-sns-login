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
	// state check
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

	// Get Tokens
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

	// Validate id_token signature
	idToken, err := oidc.NewIdToken(tokenResp.IdToken)
	if err != nil {
		fmt.Println(err)
		return
	}
	if err := idToken.ValidateSignature(client.JwksEndpoint); err != nil {
		fmt.Println(err)
		return
	}

	// Validate payload
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

	user := model.User{Email: payload.Email, Sub: payload.Sub, IdProvider: payload.Iss}
	if err = user.Create(db); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Success!")
}
