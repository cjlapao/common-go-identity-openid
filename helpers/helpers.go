package helpers

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/cjlapao/common-go-identity-oauth2/adapters"
)

func GetCookieName(client adapters.OAuth2Provider) string {
	return fmt.Sprintf("%s_%s", client.Name(), LOGIN_COOKIE_SUFFIX)
}

func GenerateStateOauthCookie(client adapters.OAuth2Provider, cookieExpiration time.Duration, w http.ResponseWriter) string {
	var expiration = time.Now().UTC().Add(cookieExpiration)
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{
		Name:     GetCookieName(client),
		Value:    state,
		Expires:  expiration,
		HttpOnly: true,
		Secure:   true,
	}

	http.SetCookie(w, &cookie)

	return state
}
