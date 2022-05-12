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
	"net/url"
	"sns-login/model"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

var (
	errIssMismatch    = errors.New("id_token issuer invalid")
	errAudMismatch    = errors.New("id_token audience mismatch")
	errIdTokenExpired = errors.New("id_token expired")
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

func (token idToken) ValidateSignature(jwksUrl string) error {
	parsedUrl, err := url.Parse(jwksUrl)
	if err != nil {
		return err
	}

	resp, err := http.Get(parsedUrl.String())
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			panic(err)
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

	const standardExponent = 65537
	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(byteN),
		E: standardExponent, // TODO: key.E -> "AQAB"から導きたい
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

	return 0, errIssMismatch
}
