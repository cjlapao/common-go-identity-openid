package oauth2context

type Oauth2ContextOptions struct {
	BaseDomain       string
	ControllerPrefix string
}

func NewOAuthContextOptions() *Oauth2ContextOptions {
	return &Oauth2ContextOptions{
		ControllerPrefix: "auth",
	}
}
