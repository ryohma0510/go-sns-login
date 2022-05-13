package oidc

type clientSecret string

const secretMaskingStr = "[CLIENT SECRET MASKED]"

// String はclient_secretがログに出力されないようにマスクする
func (s clientSecret) String() string {
	return secretMaskingStr
}

// GoString はclient_secretがログに出力されないようにマスクする
func (s clientSecret) GoString() string {
	return secretMaskingStr
}
