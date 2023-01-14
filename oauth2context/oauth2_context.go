package oauth2context

import (
	"strings"

	"github.com/cjlapao/common-go-identity-oauth2/adapters"
	restapi "github.com/cjlapao/common-go-restapi"
	"github.com/cjlapao/common-go/helper/http_helper"
	"github.com/cjlapao/common-go/log"
)

var globalContext *Oauth2Context
var logger = log.Get()

type Oauth2Context struct {
	listener            *restapi.HttpListener
	providers           []adapters.OAuth2Provider
	Options             *Oauth2ContextOptions
	SuccessCallbackPath string
	ErrorCallbackPath   string
}

func New(l *restapi.HttpListener, options *Oauth2ContextOptions) *Oauth2Context {
	globalContext = &Oauth2Context{
		Options:   options,
		listener:  l,
		providers: make([]adapters.OAuth2Provider, 0),
	}

	return globalContext
}

func Get() *Oauth2Context {
	return globalContext
}

func (ctx *Oauth2Context) GetSuccessCallbackRedirectPath() string {
	if ctx.SuccessCallbackPath == "" {
		return "/"
	}

	return ctx.SuccessCallbackPath
}

func (ctx *Oauth2Context) GetErrorCallbackRedirectPath() string {
	if ctx.SuccessCallbackPath == "" {
		return "/"
	}

	return ctx.SuccessCallbackPath
}

func (ctx *Oauth2Context) RegisterProvider(provider adapters.OAuth2Provider) {
	found := false
	for _, p := range ctx.providers {
		if strings.EqualFold(p.Name(), provider.Name()) {
			found = true
			break
		}
	}

	if !found {
		ctx.providers = append(ctx.providers, provider)
		if ctx.listener != nil {
			ctx.listener.AddController(provider.Login(), http_helper.JoinUrl(ctx.Options.ControllerPrefix, provider.Name(), "login"), "GET")
			ctx.listener.AddController(provider.Logout(), http_helper.JoinUrl(ctx.Options.ControllerPrefix, provider.Name(), "logout"), "GET")
			ctx.listener.AddController(provider.Callback(), http_helper.JoinUrl(ctx.Options.ControllerPrefix, provider.Name(), "callback"), "GET")
		} else {
			logger.Warn("Unable to initialize the %s openid provider as there is no default listener initialized", provider.Name())
		}
	}
}
