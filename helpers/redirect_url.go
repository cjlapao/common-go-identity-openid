package helpers

import (
	"fmt"

	"github.com/cjlapao/common-go-identity-openid/oauth2context"
)

type OAuth2Url struct {
	protocol string
	host     string
	client   string
	endpoint string
}

func NewOAuth2Url(host, client, endpoint string) *OAuth2Url {
	return &OAuth2Url{
		protocol: "http",
		host:     host,
		client:   client,
		endpoint: endpoint,
	}
}

func (r *OAuth2Url) String() string {
	prefix := ""
	currentAuth := oauth2context.Get()
	if currentAuth != nil {
		prefix = currentAuth.Options.ControllerPrefix
	}

	u := fmt.Sprintf("%s://%s", r.protocol, r.host)
	if prefix != "" {
		u = fmt.Sprintf("%s/%s", u, prefix)
	}

	if r.client != "" {
		u = fmt.Sprintf("%s/%s", u, r.client)
	}

	if r.endpoint != "" {
		u = fmt.Sprintf("%s/%s", u, r.endpoint)
	}

	return u
}

func (r *OAuth2Url) SetTls() {
	r.protocol = "https"
}

func (r *OAuth2Url) GetTls() string {
	r.protocol = "https"
	return r.String()
}

func (r *OAuth2Url) Get() string {
	return r.String()
}
