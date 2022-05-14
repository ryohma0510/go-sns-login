package oidc

import (
	"errors"
	"time"
)

var yahooIssuers = [1]string{"https://auth.login.yahoo.co.jp/yconnect/v2"}

type yahooIdTokenPayload struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	// Aud が配列になっていることに注意
	Aud []string `json:"aud"`
	Exp int64    `json:"exp"`
}

func (p yahooIdTokenPayload) validateIss() error {
	for _, v := range yahooIssuers {
		if p.Iss == v {
			return nil
		}
	}

	return errIssMismatch
}

func (p yahooIdTokenPayload) validateAud(clientId string) error {
	for _, v := range p.Aud {
		if v == clientId {
			return nil
		}
	}

	return errAudMismatch
}

func (p yahooIdTokenPayload) validateExp() error {
	if (time.Now().Unix() - p.Exp) > 0 {
		return errIdTokenExpired
	}

	return nil
}

func (p yahooIdTokenPayload) validate(clientId string) error {
	if err := p.validateIss(); err != nil {
		return err
	}

	if err := p.validateAud(clientId); err != nil {
		return err
	}

	if err := p.validateExp(); err != nil {
		return err
	}

	return nil
}

func (p yahooIdTokenPayload) GetEmail() (string, error) {
	return "", errors.New("cannot get email from yahoo id_token payload")
}

func (p yahooIdTokenPayload) GetSub() string {
	return p.Sub
}
