package google_provider

import (
	"fmt"
	"strings"
	"time"

	"github.com/cjlapao/common-go-identity-oauth2/adapters"
	"github.com/cjlapao/common-go-identity-oauth2/helpers"
	"github.com/cjlapao/common-go-identity-oauth2/oauth2context"
	log "github.com/cjlapao/common-go-logger"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var logger = log.Get()

type GoogleOauth2Client struct {
	context               *oauth2context.Oauth2Context
	profileApiUrl         string
	callbackRedirectUrl   *helpers.OAuth2Url
	errorRedirectPath     string
	loggedInRedirectPath  string
	loggedOutRedirectPath string
	config                *oauth2.Config
	tokenExpiration       time.Duration
	RedirectOnSuccess     bool
	RedirectOnError       bool
	LoggedInCallback      func(*adapters.OAuth2CallbackResponse) error
	LoggedOutCallback     func(*adapters.OAuth2CallbackResponse) error
	ErrorCallback         func(*adapters.OAuth2CallbackResponse) error
}

func New(clientId string, clientSecret string) *GoogleOauth2Client {
	client := &GoogleOauth2Client{
		context:           oauth2context.Get(),
		profileApiUrl:     GOOGLE_OAUTH_PROFILE_API_URL,
		RedirectOnSuccess: false,
		RedirectOnError:   false,
		tokenExpiration:   helpers.DEFAULT_COOKIE_EXPIRATION,
	}

	if client.context == nil {
		logger.Error("Context cannot be nil for google provider")
		return nil
	}

	client.callbackRedirectUrl = helpers.NewOAuth2Url(client.context.Options.BaseDomain, GOOGLE_DEFAULT_CLIENT_NAME, GOOGLE_CALLBACK_ENDPOINT)
	client.errorRedirectPath = "/"
	client.loggedInRedirectPath = "/"
	client.loggedOutRedirectPath = "/"
	client.profileApiUrl = GOOGLE_OAUTH_PROFILE_API_URL

	client.config = &oauth2.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	return client
}

func (c *GoogleOauth2Client) Name() string {
	return GOOGLE_DEFAULT_CLIENT_NAME
}

func (c *GoogleOauth2Client) Scopes() []string {
	return c.config.Scopes
}

func (c *GoogleOauth2Client) AppendScope(scope string) {
	found := false
	for _, configScope := range c.config.Scopes {
		if strings.EqualFold(configScope, scope) {
			found = true
			break
		}
	}

	if !found {
		c.config.Scopes = append(c.config.Scopes, scope)
	}
}

func (c *GoogleOauth2Client) RemoveScope(scope string) {
	found := false
	for _, configScope := range c.config.Scopes {
		if strings.EqualFold(configScope, scope) {
			found = true
			break
		}
	}

	if found {
		newSet := make([]string, len(c.config.Scopes)-1)
		for _, configScope := range c.config.Scopes {
			if !strings.EqualFold(configScope, scope) {
				newSet = append(newSet, configScope)
			}
		}
		c.config.Scopes = newSet
	}
}

func (c *GoogleOauth2Client) SetLoggedInRedirectPath(path string) {
	if path == "" {
		path = "/"
	}

	c.loggedInRedirectPath = path
}

func (c *GoogleOauth2Client) SetLoggedOutInRedirectPath(path string) {
	if path == "" {
		path = "/"
	}

	c.loggedOutRedirectPath = path
}

func (c *GoogleOauth2Client) SetErrorRedirectPath(path string) {
	if path == "" {
		path = "/"
	}

	c.errorRedirectPath = path
}

func (c *GoogleOauth2Client) ToggleErrorRedirect(value bool) {
	c.RedirectOnError = value
}

func (c *GoogleOauth2Client) ToggleSuccessRedirect(value bool) {
	c.RedirectOnSuccess = value
}

func (c *GoogleOauth2Client) SetErrorCallback(f func(*adapters.OAuth2CallbackResponse) error) {
	c.ErrorCallback = f
}

func (c *GoogleOauth2Client) SetLoggedInCallback(f func(*adapters.OAuth2CallbackResponse) error) {
	c.LoggedInCallback = f
}

func (c *GoogleOauth2Client) SetLoggedOutCallback(f func(*adapters.OAuth2CallbackResponse) error) {
	c.LoggedOutCallback = f
}

func Register(options adapters.OAuth2ProviderOptions) (adapters.OAuth2Provider, error) {
	client := New(options.ClientId, options.ClientSecret)

	if client.context == nil {
		err := fmt.Errorf("OAuth context cannot be nil you will need to initialize it first")
		logger.Exception(err, "There was an error adding google openid provider")
		return nil, err
	}
	if client.context.Options.BaseDomain == "" {
		//lint:ignore ST1005 // Good formatting
		err := fmt.Errorf("Base Domain cannot be empty")
		logger.Exception(err, "There was an error adding google openid provider")
		return nil, err
	}

	if options.ClientId == "" {
		err := fmt.Errorf("ClientId cannot be empty")
		logger.Exception(err, "There was an error adding google openid provider")
		return nil, err
	}

	if options.ClientSecret == "" {
		err := fmt.Errorf("ClientId cannot be empty")
		logger.Exception(err, "There was an error adding google openid provider")
		return nil, err
	}

	if options.ErrorCallbackRedirectPath != "" {
		client.SetErrorRedirectPath(options.ErrorCallbackRedirectPath)
	} else {
		client.SetErrorRedirectPath(client.context.GetErrorCallbackRedirectPath())
	}

	if options.ErrorCallbackRedirectPath != "" {
		client.SetLoggedInRedirectPath(options.ErrorCallbackRedirectPath)
	} else {
		client.SetLoggedInRedirectPath(client.context.GetSuccessCallbackRedirectPath())
	}

	client.ToggleErrorRedirect(options.ErrorCallBackRedirect)
	client.ToggleSuccessRedirect(options.SuccessCallBackRedirect)

	if options.LoggedInCallback != nil {
		client.LoggedInCallback = options.LoggedInCallback
	}

	if options.LoggedOutCallback != nil {
		client.LoggedInCallback = options.LoggedOutCallback
	}

	if options.ErrorCallback != nil {
		client.ErrorCallback = options.ErrorCallback
	}

	client.context.RegisterProvider(client)

	return client, nil
}
