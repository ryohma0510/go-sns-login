package oidc

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"sns-login/model"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

var (
	ErrIssMismatch    = errors.New("id_token issuer invalid")
	ErrAudMismatch    = errors.New("id_token audience mismatch")
	ErrIdTokenExpired = errors.New("id_token expired")
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

type jwks struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	E   string `json:"e"`
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	Alg string `json:"alg"`
}

var (
	GoogleIssuers = [2]string{"https://accounts.google.com", "accounts.google.com"}
)

// NewIdToken はJWTから構造体返す。セグメントが分割できるかのみチェックしている
func NewIdToken(rawToken string) (*idToken, error) {
	segments := strings.Split(rawToken, ".")
	if len(segments) != 3 {
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

func (token idToken) ValidateSignature(jwksUrl string) error {
	resp, err := http.Get(jwksUrl)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {

		}
	}(resp.Body)
	byteArray, _ := ioutil.ReadAll(resp.Body)
	keys := &jwks{}
	if err := json.Unmarshal(byteArray, keys); err != nil {
		return err
	}

	var key jwk
	var isFound bool
	for _, v := range keys.Keys {
		if token.header.Kid == v.Kid {
			key = v
			isFound = true
		}
	}
	if !isFound {
		return errors.New("JWK not found")
	}

	byteN, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return err
	}
	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(byteN),
		E: 65537, // TODO: key.E -> "AQAB"から導きたい
	}

	headerAndPayload := fmt.Sprintf("%s.%s", token.rawHeader, token.RawPayload)
	sha := sha256.New()
	sha.Write([]byte(headerAndPayload))

	decSignature, err := base64.RawURLEncoding.DecodeString(token.rawSignature)
	if err != nil {
		return err
	}

	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, sha.Sum(nil), decSignature); err != nil {
		return err
	}

	return nil
}

func IssToIdProvider(iss string) (model.IdProvider, error) {
	googleIdTokenPayload := GoogleIdTokenPayload{
		Iss: iss,
	}
	if err := googleIdTokenPayload.isValidIss(); err == nil {
		return model.Google, nil
	}

	return 0, ErrIssMismatch
}
