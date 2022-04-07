package oidc

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type oidcClient struct {
	idProvider    string
	clientId      string
	authEndpoint  string
	tokenEndpoint string
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
	IdToken     string `json:"id_token"`
}

func newOidcClient(idProvider string, clientId string, authEndpoint string, tokenEndpoint string) *oidcClient {
	return &oidcClient{
		idProvider:    idProvider,
		clientId:      clientId,
		authEndpoint:  authEndpoint,
		tokenEndpoint: tokenEndpoint,
	}
}

func NewGoogleOidcClient() *oidcClient {
	return newOidcClient(
		"Google",
		os.Getenv("GOOGLE_CLIENT_ID"),
		"https://accounts.google.com/o/oauth2/v2/auth",
		"https://oauth2.googleapis.com/token")
}

func (c oidcClient) AuthUrl(respType string, scopes []string, redirectUrl string, state string) string {
	return fmt.Sprintf(
		"%s?client_id=%s&response_type=%s&scope=%s&redirect_uri=%s&state=%s",
		c.authEndpoint,
		c.clientId,
		respType,
		strings.Join(scopes, "%20"),
		redirectUrl,
		state,
	)
}

func (c oidcClient) PostTokenEndpoint(code string, redirectUrl string, grantType string) (tokenResponse, error) {
	values := url.Values{}
	values.Add("code", code)
	values.Add("client_id", c.clientId)
	values.Add("client_secret", c.clientSecret())
	values.Add("redirect_uri", redirectUrl)
	values.Add("grant_type", grantType)

	resp, err := http.PostForm(c.tokenEndpoint, values)
	if err != nil {
		return tokenResponse{}, err
	}
	defer resp.Body.Close()
	bRespBody, _ := ioutil.ReadAll(resp.Body)

	tokenResp := &tokenResponse{}
	if err := json.Unmarshal(bRespBody, tokenResp); err != nil {
		return tokenResponse{}, err
	}

	return *tokenResp, nil
}

func RandomState() (string, error) {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// 乱数を生成
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return "", errors.New("unexpected error...")
	}

	// letters からランダムに取り出して文字列を生成
	var result string
	for _, v := range b {
		// index が letters の長さに収まるように調整
		result += string(letters[int(v)%len(letters)])
	}
	return result, nil
}

// private

func (c oidcClient) clientSecret() string {
	switch c.idProvider {
	case "Google":
		return os.Getenv("GOOGLE_CLIENT_SECRET")
	}

	return ""
}
