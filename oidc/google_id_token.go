package oidc

import (
	"time"
)

var (
	// refs: https://developers.google.com/identity/protocols/oauth2/openid-connect#validatinganidtoken
	googleIssuers = [2]string{"https://accounts.google.com", "accounts.google.com"}
)

// googleIdTokenPayload はトークンエンドポイントのレスポンスの中のid_tokenのpayloadをunmarshalするための構造体
type googleIdTokenPayload struct {
	Iss string `json:"iss"`
	// クライアントID
	Aud string `json:"aud"`
	// ID Provider内でのID。メアドではなくこちらがユーザー識別子となる
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Exp   int64  `json:"exp"`
}

// Validate はpayloadの中身を検証
//
// - Issuer
//
// - Audience
//
// - Expiration
//
// を確認する
func (payload googleIdTokenPayload) validate(clientId string) error {
	if err := payload.validateIss(); err != nil {
		return err
	}

	if err := payload.validateAud(clientId); err != nil {
		return err
	}

	if err := payload.validateExp(); err != nil {
		return err
	}

	return nil
}

func (payload googleIdTokenPayload) validateIss() error {
	isValid := false
	for _, v := range googleIssuers {
		if payload.Iss == v {
			isValid = true
		}
	}

	if isValid {
		return nil
	} else {
		return errIssMismatch
	}
}

func (payload googleIdTokenPayload) validateAud(clientId string) error {
	if payload.Aud != clientId {
		return errAudMismatch
	}

	return nil
}

func (payload googleIdTokenPayload) validateExp() error {
	if (time.Now().Unix() - payload.Exp) > 0 {
		return errIdTokenExpired
	}

	return nil
}

func (payload googleIdTokenPayload) GetSub() string {
	return payload.Sub
}

// GetEmail はid_tokenからメールアドレスを取得する
//
// Googleの場合はid_tokenにメールアドレスが入っているが、IdPによっては入っていないので、UserInfo Endpointから取得する必要がある
func (payload googleIdTokenPayload) GetEmail() (string, error) {
	return payload.Email, nil
}
