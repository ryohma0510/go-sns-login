package oidc

import (
	"errors"
	"time"
)

// GoogleIdTokenPayload はトークンエンドポイントのレスポンスの中のid_tokenのpayloadをunmarshalするための構造体
type GoogleIdTokenPayload struct {
	Iss string `json:"iss"`
	Azp string `json:"azp"`
	// クライアントID
	Aud string `json:"aud"`
	// ID Provider内でのID。メアドではなくこちらがユーザー識別子となる
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	AtHash        string `json:"at_hash"`
	Nonce         string `json:"nonce"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Locale        string `json:"locale"`
	Iat           int64  `json:"iat"`
	Exp           int64  `json:"exp"`
}

// IsValid はpayloadの中身を検証
func (payload GoogleIdTokenPayload) IsValid(clientId string) error {
	if err := payload.isValidIss(); err != nil {
		return err
	}

	if err := payload.isValidAud(clientId); err != nil {
		return err
	}

	if err := payload.isValidExp(); err != nil {
		return err
	}

	return nil
}

func (payload GoogleIdTokenPayload) isValidIss() error {
	isValid := false
	validIssuers := [2]string{"https://accounts.google.com", "accounts.google.com"}
	for _, v := range validIssuers {
		if payload.Iss == v {
			isValid = true
		}
	}

	if isValid {
		return nil
	} else {
		return errors.New("id_token issuer invalid")
	}
}

func (payload GoogleIdTokenPayload) isValidAud(clientId string) error {
	if payload.Aud != clientId {
		return errors.New("id_token audience mismatch")
	}

	return nil
}

func (payload GoogleIdTokenPayload) isValidExp() error {
	if (time.Now().Unix() - payload.Exp) > 0 {
		return errors.New("id_token expired")
	}

	return nil
}
