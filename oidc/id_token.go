package oidc

import (
	"encoding/json"
	"errors"
	"sns-login/model"
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
	rawToken     string
	rawHeader    string
	RawPayload   string
	rawSignature string
	header       header
}

type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

var (
	googleIssuers = [2]string{"https://accounts.google.com", "accounts.google.com"}
)

// NewIdToken はJWTから構造体返す。セグメントが分割できるかのみチェックしている
func NewIdToken(rawToken string) (*idToken, error) {
	const jwtSegNum = 3
	segments := strings.Split(rawToken, ".")
	if len(segments) != jwtSegNum {
		return nil, errors.New("invalid jwt")
	}
	idToken := &idToken{
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

	return idToken, nil
}

func IssToIdProvider(iss string) (model.IdProvider, error) {
	googleIdTokenPayload := GoogleIdTokenPayload{
		Iss: iss,
	}
	if err := googleIdTokenPayload.isValidIss(); err == nil {
		return model.Google, nil
	}

	return 0, errIssMismatch
}
