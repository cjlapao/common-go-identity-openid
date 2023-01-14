package adapters

import (
	"github.com/cjlapao/common-go-restapi/controllers"
)

type OAuth2Provider interface {
	Name() string
	Scopes() []string
	AppendScope(scope string)
	RemoveScope(scope string)
	Login() controllers.Controller
	Logout() controllers.Controller
	Callback() controllers.Controller
	SetLoggedInRedirectPath(path string)
	SetLoggedOutInRedirectPath(path string)
	SetErrorRedirectPath(path string)
	ToggleErrorRedirect(value bool)
	ToggleSuccessRedirect(value bool)
	SetErrorCallback(f func(*OAuth2CallbackResponse) error)
	SetLoggedInCallback(f func(*OAuth2CallbackResponse) error)
	SetLoggedOutCallback(f func(*OAuth2CallbackResponse) error)
}
