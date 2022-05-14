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

type IClient interface {
	AuthUrl(respType string, scopes []string, redirectUrl string, state string) string
	PostTokenEndpoint(code string, redirectUrl string, grantType string) (tokenResponse, error)
	PostUserInfoEndpoint(accessToken string) (userInfoResponse, error)
	ValidateIdToken(token IdToken) error
}

type client struct {
	IdProvider
	ClientId         string
	clientSecret     clientSecret
	authEndpoint     string
	tokenEndpoint    string
	JwksEndpoint     string
	userInfoEndpoint string
}

// tokenResponse はトークンエンドポイントのレスポンスをunmarshalするため構造体
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
	IdToken     string `json:"id_token"`
}

type userInfoResponse struct {
	Email string `json:"email"`
}

// NewGoogleOidcClient はGoogleのクライアントを返す
func NewGoogleOidcClient() IClient {
	return client{
		IdProvider:    Google,
		ClientId:      os.Getenv("GOOGLE_CLIENT_ID"),
		clientSecret:  clientSecret(os.Getenv("GOOGLE_CLIENT_SECRET")),
		authEndpoint:  "https://accounts.google.com/o/oauth2/v2/auth",
		tokenEndpoint: "https://oauth2.googleapis.com/token",
		JwksEndpoint:  "https://www.googleapis.com/oauth2/v3/certs",
	}
}

func NewYahooOidcClient() IClient {
	return client{
		IdProvider:       Yahoo,
		ClientId:         os.Getenv("YAHOO_CLIENT_ID"),
		clientSecret:     clientSecret(os.Getenv("YAHOO_CLIENT_SECRET")),
		authEndpoint:     "https://auth.login.yahoo.co.jp/yconnect/v2/authorization",
		tokenEndpoint:    "https://auth.login.yahoo.co.jp/yconnect/v2/token",
		JwksEndpoint:     "https://auth.login.yahoo.co.jp/yconnect/v2/jwks",
		userInfoEndpoint: "https://userinfo.yahooapis.jp/yconnect/v2/attribute",
	}
}

// AuthUrl は認可エンドポイントのURLを返す
func (c client) AuthUrl(respType string, scopes []string, redirectUrl string, state string) string {
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
func (c client) PostTokenEndpoint(code string, redirectUrl string, grantType string) (tokenResponse, error) {
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

func (c client) PostUserInfoEndpoint(accessToken string) (userInfoResponse, error) {
	values := url.Values{}
	values.Add("access_token", accessToken)

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), httpTimeoutSec*time.Second)
	defer cancel()
	reqWithCtx, err := http.NewRequestWithContext(
		ctxWithTimeout,
		http.MethodPost,
		c.userInfoEndpoint,
		strings.NewReader(values.Encode()),
	)
	if err != nil {
		return userInfoResponse{}, fmt.Errorf("failed to create request of POST token endpoint: %w", err)
	}
	reqWithCtx.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpClient := &http.Client{}
	resp, err := httpClient.Do(reqWithCtx)
	if err != nil {
		return userInfoResponse{}, fmt.Errorf("failed to POST user info endpoint: %w", err)
	}
	defer func(body io.ReadCloser) {
		err := body.Close()
		if err != nil {
			panic(err)
		}
	}(resp.Body)
	bRespBody, _ := ioutil.ReadAll(resp.Body)

	userInfoResp := &userInfoResponse{}
	if err := json.Unmarshal(bRespBody, userInfoResp); err != nil {
		return userInfoResponse{}, fmt.Errorf("failed to unmarshal user info response: %w", err)
	}

	return *userInfoResp, nil
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
