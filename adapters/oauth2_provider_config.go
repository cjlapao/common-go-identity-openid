package adapters

type OAuth2ProviderOptions struct {
	ClientSecret                  string
	ClientId                      string
	LoggedInCallback              func(*OAuth2CallbackResponse) error
	LoggedInCallbackRedirectPath  string
	LoggedOutCallback             func(*OAuth2CallbackResponse) error
	LoggedOutCallbackRedirectPath string
	ErrorCallback                 func(*OAuth2CallbackResponse) error
	ErrorCallBackRedirect         bool
	ErrorCallbackRedirectPath     string
	SuccessCallBackRedirect       bool
}
