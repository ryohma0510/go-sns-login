// Package oidc はOpenIDConnectで共通の実装を管理します
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

type Client struct {
	idProvider    string
	ClientId      string
	authEndpoint  string
	tokenEndpoint string
	JwksEndpoint  string
}

// tokenResponse はトークンエンドポイントのレスポンスをunmarshalするため構造体
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
	IdToken     string `json:"id_token"`
}

func newOidcClient(idProvider string, clientId string, authEndpoint string, tokenEndpoint string, jwksEndpoint string) *Client {
	return &Client{
		idProvider:    idProvider,
		ClientId:      clientId,
		authEndpoint:  authEndpoint,
		tokenEndpoint: tokenEndpoint,
		JwksEndpoint:  jwksEndpoint,
	}
}

// NewGoogleOidcClient はGoogleのクライアントを返す
func NewGoogleOidcClient() *Client {
	return newOidcClient(
		"google",
		os.Getenv("GOOGLE_CLIENT_ID"),
		"https://accounts.google.com/o/oauth2/v2/auth",
		"https://oauth2.googleapis.com/token",
		"https://www.googleapis.com/oauth2/v3/certs",
	)
}

// AuthUrl は認可エンドポイントのURLを返す
func (c Client) AuthUrl(respType string, scopes []string, redirectUrl string, state string) string {
	return fmt.Sprintf(
		"%s?client_id=%s&response_type=%s&scope=%s&redirect_uri=%s&state=%s",
		c.authEndpoint,
		c.ClientId,
		respType,
		strings.Join(scopes, "%20"),
		redirectUrl,
		state,
	)
}

// PostTokenEndpoint はトークンエンドポイントに認可コードを渡してトークンを得る
func (c Client) PostTokenEndpoint(code string, redirectUrl string, grantType string) (tokenResponse, error) {
	values := url.Values{}
	values.Add("code", code)
	values.Add("client_id", c.ClientId)
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

// RandomState はCSRF攻撃の対策に使うためにランダムな文字列を返す。
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

// clientSecret は環境変数に登録されたシークレットを取り出す
func (c Client) clientSecret() string {
	switch c.idProvider {
	case "google":
		return os.Getenv("GOOGLE_CLIENT_SECRET")
	}

	return ""
}
