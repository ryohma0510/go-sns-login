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

type idToken struct {
	IdProvider
	rawToken     string
	rawHeader    string
	RawPayload   string
	rawSignature string
	header
	Payload idTokenPayload
}

type idTokenPayload interface {
	validateIss() error
	validateAud(clientId string) error
	validateExp() error
	validate(clientId string) error
	GetSub() string
	// GetEmail はGoogleでのみ動作する
	GetEmail() (string, error)
}

type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// NewIdToken は生のJWTからheaderとpayloadを焼き直した構造体返す。
func NewIdToken(rawToken string, provider IdProvider) (*idToken, error) {
	const jwtSegNum = 3
	segments := strings.Split(rawToken, ".")
	if len(segments) != jwtSegNum {
		return nil, errors.New("invalid jwt")
	}
	idToken := &idToken{
		IdProvider:   provider,
		rawToken:     rawToken,
		rawHeader:    segments[0],
		RawPayload:   segments[1],
		rawSignature: segments[2],
	}

	byteHeader, err := jwt.DecodeSegment(idToken.rawHeader)
	if err != nil {
		return nil, errors.New("base64 decode header error")
	}
	header := &header{}
	if err := json.Unmarshal(byteHeader, header); err != nil {
		return nil, errors.New("json decode header error")
	}
	idToken.header = *header

	// payloadのセット
	if err := idToken.setPayload(); err != nil {
		return nil, err
	}

	return idToken, nil
}

// setPayload は生のpayloadを構造体に焼き直してセットする
func (token *idToken) setPayload() error {
	if token.IdProvider == Google {
		bytePayload, err := jwt.DecodeSegment(token.RawPayload)
		if err != nil {
			return fmt.Errorf("failed to decode payload JWT segment: %w", err)
		}
		payload := &googleIdTokenPayload{}
		if err := json.Unmarshal(bytePayload, payload); err != nil {
			return fmt.Errorf("failed to unmarshal id_token payload: %w", err)
		}
		token.Payload = payload

		return nil
	}

	return errIssMismatch
}

// Validate はJWTの署名とpayloadの中身を検証する
func (token idToken) Validate(jwksUrl string, clientId string) error {
	if err := token.validateSignature(jwksUrl); err != nil {
		return err
	}

	if err := token.Payload.validate(clientId); err != nil {
		return fmt.Errorf("failed to validate id_token payload: %w", err)
	}

	return nil
}
