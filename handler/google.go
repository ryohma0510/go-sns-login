package handler

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"os"
	"sns-login/oidc"
	"strings"
)

func AuthGoogleHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("aaaaa")
	client := oidc.NewGoogleOidcClient()

	state, err := oidc.RandomState()
	if err != nil {
		fmt.Println(err)
	}

	redirectUrl := client.AuthUrl(
		"code",
		[]string{"openid", "email", "profile"},
		fmt.Sprintf("%s:%s/auth/google/callback", os.Getenv("SERVER_HOST"), os.Getenv("SERVER_PORT")),
		state,
	)

	http.Redirect(w, r, redirectUrl, 301)
}

func AuthGoogleCallbackHandler(w http.ResponseWriter, r *http.Request) {
	queryState := r.URL.Query().Get("state")
	sessionState := queryState // dummy
	if queryState != sessionState {
		fmt.Printf("state does not match %s : %s", queryState, sessionState)
		panic("")
	}

	client := oidc.NewGoogleOidcClient()
	tokenResp, err := client.PostTokenEndpoint(
		r.URL.Query().Get("code"),
		fmt.Sprintf("%s:%s/auth/google/callback", os.Getenv("SERVER_HOST"), os.Getenv("SERVER_PORT")),
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

	fmt.Printf("Got sub: %s", googleIdToken.Sub)
}
