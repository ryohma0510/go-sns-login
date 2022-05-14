package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

var (
	errIssMismatch    = errors.New("id_token issuer invalid")
	errAudMismatch    = errors.New("id_token audience mismatch")
	errIdTokenExpired = errors.New("id_token expired")
	errJwkNotFound    = errors.New("key not found on JWKs endpoint")
)

type IdToken struct {
	IdProvider
	rawToken     string
	rawHeader    string
	RawPayload   string
	rawSignature string
	header
	Payload iIdTokenPayload
}

type iIdTokenPayload interface {
	validateIss() error
	validateAud(clientId string) error
	validateExp() error
	validate(clientId string) error
	GetEmail() (string, error)
	GetSub() string
}

type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// NewIdToken は生のJWTからheaderとpayloadを焼き直した構造体返す。
func NewIdToken(rawToken string, provider IdProvider) (IdToken, error) {
	const jwtSegNum = 3
	segments := strings.Split(rawToken, ".")
	if len(segments) != jwtSegNum {
		return IdToken{}, errors.New("invalid jwt")
	}
	token := IdToken{
		IdProvider:   provider,
		rawToken:     rawToken,
		rawHeader:    segments[0],
		RawPayload:   segments[1],
		rawSignature: segments[2],
	}

	byteHeader, err := jwt.DecodeSegment(token.rawHeader)
	if err != nil {
		return IdToken{}, errors.New("base64 decode header error")
	}
	header := &header{}
	if err := json.Unmarshal(byteHeader, header); err != nil {
		return IdToken{}, errors.New("json decode header error")
	}
	token.header = *header

	// payloadのセット
	if err := token.setPayload(); err != nil {
		return IdToken{}, err
	}

	return token, nil
}

// setPayload は生のpayloadを構造体に焼き直してセットする
func (token *IdToken) setPayload() error {
	bytePayload, err := jwt.DecodeSegment(token.RawPayload)
	if err != nil {
		return fmt.Errorf("failed to decode payload JWT segment: %w", err)
	}

	var payload iIdTokenPayload
	switch token.IdProvider {
	case Google:
		payload = &googleIdTokenPayload{}
	case Yahoo:
		payload = &yahooIdTokenPayload{}
	default:
		return errIssMismatch
	}

	if err := json.Unmarshal(bytePayload, payload); err != nil {
		return fmt.Errorf("failed to unmarshal id_token payload: %w", err)
	}
	token.Payload = payload

	return nil
}
