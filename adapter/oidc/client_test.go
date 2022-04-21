package oidc

import (
	"github.com/jarcoal/httpmock"
	"testing"
)

func TestOidcClient_AuthUrl(t *testing.T) {
	patterns := []struct {
		desc        string
		client      *Client
		respType    string
		scopes      []string
		redirectUrl string
		state       string
		expected    string
	}{
		{
			"",
			NewGoogleOidcClient(),
			"code",
			[]string{"openid", "email", "profile"},
			"http://localhost:8000/auth/google/sign_up/callback",
			"12345678",
			"https://accounts.google.com/o/oauth2/v2/auth?client_id=&response_type=code&scope=openid%20email%20profile&redirect_uri=http://localhost:8000/auth/google/sign_up/callback&state=12345678",
		},
		{
			"scopeが一個の時にエラーにならないか",
			NewGoogleOidcClient(),
			"code",
			[]string{"profile"},
			"http://localhost:8000/auth/google/sign_up/callback",
			"12345678",
			"https://accounts.google.com/o/oauth2/v2/auth?client_id=&response_type=code&scope=profile&redirect_uri=http://localhost:8000/auth/google/sign_up/callback&state=12345678",
		},
	}

	for idx, pattern := range patterns {
		actual := pattern.client.AuthUrl(
			pattern.respType,
			pattern.scopes,
			pattern.redirectUrl,
			pattern.state,
		)
		if pattern.expected != actual {
			t.Errorf("pattern %d: want %s, actual %s", idx, pattern.expected, actual)
		}
	}
}

func TestOidcClient_PostTokenEndpoint(t *testing.T) {
	client := NewGoogleOidcClient()

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	httpmock.RegisterResponder("POST", client.tokenEndpoint,
		httpmock.NewStringResponder(
			200,
			`{
     "access_token": "DummyAccessToken",
     "expires_in": 3566,
     "scope": "openid https://www.googleapis.com/auth/userinfo.email",
     "token_type": "Bearer",
     "id_token": "DummyIdToken"
 }
`,
		),
	)

	actual, _ := client.PostTokenEndpoint("", "", "")
	expected := tokenResponse{
		AccessToken: "DummyAccessToken",
		ExpiresIn:   3566,
		Scope:       "openid https://www.googleapis.com/auth/userinfo.email",
		TokenType:   "Bearer",
		IdToken:     "DummyIdToken",
	}

	if actual != expected {
		t.Errorf("want %v, actual %v", expected, actual)
	}
}

func TestRandomState(t *testing.T) {
	if _, err := RandomState(); err != nil {
		t.Error(err)
	}
}
