package oidc

import (
	"time"
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

func (payload googleIdTokenPayload) GetEmail() (string, error) {
	return payload.Email, nil
}
