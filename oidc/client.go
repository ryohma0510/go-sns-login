// Package oidc はOpenIDConnectで共通の実装を管理します
package oidc

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const httpTimeoutSec = 10

type oidcClient struct {
	IdProvider
	ClientId      string
	clientSecret  clientSecret
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

func newOidcClient(
	idProvider IdProvider,
	clientId string,
	clientSecret clientSecret,
	authEndpoint string,
	tokenEndpoint string,
	jwksEndpoint string,
) *oidcClient {
	return &oidcClient{
		IdProvider:    idProvider,
		ClientId:      clientId,
		clientSecret:  clientSecret,
		authEndpoint:  authEndpoint,
		tokenEndpoint: tokenEndpoint,
		JwksEndpoint:  jwksEndpoint,
	}
}

// NewGoogleOidcClient はGoogleのクライアントを返す
func NewGoogleOidcClient() *oidcClient {
	return newOidcClient(
		Google,
		os.Getenv("GOOGLE_CLIENT_ID"),
		clientSecret(os.Getenv("GOOGLE_CLIENT_SECRET")),
		"https://accounts.google.com/o/oauth2/v2/auth",
		"https://oauth2.googleapis.com/token",
		"https://www.googleapis.com/oauth2/v3/certs",
	)
}

// AuthUrl は認可エンドポイントのURLを返す
func (c oidcClient) AuthUrl(respType string, scopes []string, redirectUrl string, state string) string {
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
func (c oidcClient) PostTokenEndpoint(code string, redirectUrl string, grantType string) (tokenResponse, error) {
	values := url.Values{}
	values.Add("code", code)
	values.Add("client_id", c.ClientId)
	values.Add("client_secret", string(c.clientSecret))
	values.Add("redirect_uri", redirectUrl)
	values.Add("grant_type", grantType)

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), httpTimeoutSec*time.Second)
	defer cancel()
	reqWithCtx, err := http.NewRequestWithContext(
		ctxWithTimeout,
		http.MethodPost,
		c.tokenEndpoint,
		strings.NewReader(values.Encode()),
	)
	if err != nil {
		return tokenResponse{}, fmt.Errorf("failed to create request of POST token endpoint: %w", err)
	}
	reqWithCtx.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpClient := &http.Client{}
	resp, err := httpClient.Do(reqWithCtx)
	if err != nil {
		return tokenResponse{}, fmt.Errorf("failed to POST token endpoint: %w", err)
	}
	defer func(body io.ReadCloser) {
		err := body.Close()
		if err != nil {
			panic(err)
		}
	}(resp.Body)
	bRespBody, _ := ioutil.ReadAll(resp.Body)

	tokenResp := &tokenResponse{}
	if err := json.Unmarshal(bRespBody, tokenResp); err != nil {
		return tokenResponse{}, fmt.Errorf("failed to unmarshal token response: %w", err)
	}

	return *tokenResp, nil
}

// RandomState はCSRF攻撃の対策に使うためにランダムな文字列を返す。
func RandomState() (string, error) {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// 乱数を生成
	const strLength = 10
	b := make([]byte, strLength)
	if _, err := rand.Read(b); err != nil {
		return "", errors.New("unexpected error")
	}

	// letters からランダムに取り出して文字列を生成
	var result string
	for _, v := range b {
		// index が letters の長さに収まるように調整
		result += string(letters[int(v)%len(letters)])
	}

	return result, nil
}
