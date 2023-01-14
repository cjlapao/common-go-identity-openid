package helpers

import (
	"fmt"
	"testing"

	"github.com/cjlapao/common-go-identity-oauth2/oauth2context"
	"github.com/stretchr/testify/assert"
)

func TestOpenIdUrl_String(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		r      *OAuth2Url
		want   string
	}{
		{
			"without prefix",
			"",
			&OAuth2Url{
				protocol: "http",
				host:     "example.com",
				client:   "google",
				endpoint: "callback",
			},
			"http://example.com/google/callback",
		},
		{
			"with prefix",
			"auth",
			&OAuth2Url{
				protocol: "http",
				host:     "example.com",
				client:   "google",
				endpoint: "callback",
			},
			"http://example.com/auth/google/callback",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.prefix != "" {
				auth := oauth2context.New(nil, &oauth2context.Oauth2ContextOptions{
					ControllerPrefix: tt.prefix,
				})
				auth.Options.ControllerPrefix = tt.prefix
			} else {
				if oauth2context.Get() != nil {
					oauth2context.Get().Options.ControllerPrefix = ""
				}
			}
			if got := tt.r.String(); got != tt.want {
				t.Errorf("OpenIdUrl.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetTls(t *testing.T) {
	url := OAuth2Url{
		protocol: "http",
		host:     "example.com",
		client:   "facebook",
		endpoint: "callback",
	}

	result := url.GetTls()

	assert.Contains(t, result, "https://")
}

func TestGet(t *testing.T) {
	url := OAuth2Url{
		protocol: "http",
		host:     "example.com",
		client:   "facebook",
		endpoint: "callback",
	}

	result := url.Get()

	assert.Contains(t, result, "http://")
}

func TestSetTls(t *testing.T) {
	url := OAuth2Url{
		protocol: "http",
		host:     "example.com",
		client:   "facebook",
		endpoint: "callback",
	}

	expected := "http://example.com/facebook/callback"
	if oauth2context.Get() != nil {
		expected = fmt.Sprintf("http://example.com/%s/facebook/callback", oauth2context.Get().Options.ControllerPrefix)
	}

	expectedTls := "https://example.com/facebook/callback"
	if oauth2context.Get() != nil {
		expectedTls = fmt.Sprintf("https://example.com/%s/facebook/callback", oauth2context.Get().Options.ControllerPrefix)
	}

	result := url.Get()
	assert.Equal(t, expected, result)
	url.SetTls()
	resultTls := url.Get()
	assert.Equal(t, expectedTls, resultTls)
}

func TestNewRedirectUrl(t *testing.T) {
	url := NewOAuth2Url("example.com", "meta", "login")

	expected := "http://example.com/meta/login"
	if oauth2context.Get() != nil {
		expected = fmt.Sprintf("http://example.com/%s/meta/login", oauth2context.Get().Options.ControllerPrefix)
	}

	assert.Equal(t, expected, url.String())
}
