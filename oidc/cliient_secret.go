package oidc

type clientSecret string

const secretMaskingStr = "[CLIENT SECRET MASKED]"

func (s clientSecret) String() string {
	return secretMaskingStr
}

func (s clientSecret) GoString() string {
	return secretMaskingStr
}
