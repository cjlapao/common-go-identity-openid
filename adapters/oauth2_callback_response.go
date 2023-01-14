package adapters

import "strconv"

const (
	CLAIM_NAME            string = "name"
	CLAIM_EMAIL           string = "email"
	CLAIM_USERNAME        string = "username"
	CLAIM_FAMILY_NAME     string = "family_name"
	CLAIM_GIVEN_NAME      string = "given_name"
	CLAIM_PROFILE_PICTURE string = "profile_picture"
	CLAIM_LOCALE          string = "locale"
	CLAIM_VERIFIED_EMAIL  string = "verified_email"
)

type OAuth2CallbackResponse struct {
	State         Oauth2CallbackState
	Success       bool
	Error         error
	Claims        map[string]string
	Code          string
	CallbackState string
}

func (c OAuth2CallbackResponse) GetName() string {
	name := c.Claims[CLAIM_NAME]
	if name == "" {
		if c.Claims[CLAIM_GIVEN_NAME] != "" {
			name = c.Claims[CLAIM_GIVEN_NAME]
		}
		if c.Claims[CLAIM_FAMILY_NAME] != "" {
			if name != "" {
				name += " "
			}

			name += c.Claims[CLAIM_FAMILY_NAME]
		}
	}

	return name
}

func (c OAuth2CallbackResponse) GetEmail() string {
	return c.Claims[CLAIM_EMAIL]
}

func (c OAuth2CallbackResponse) GetUsername() string {
	username := c.Claims[CLAIM_USERNAME]
	if username == "" && c.Claims[CLAIM_EMAIL] != "" {
		username = c.Claims[CLAIM_EMAIL]
	}

	return username
}

func (c OAuth2CallbackResponse) GetFamilyName() string {
	return c.Claims[CLAIM_FAMILY_NAME]
}

func (c OAuth2CallbackResponse) GetGivenName() string {
	return c.Claims[CLAIM_GIVEN_NAME]
}

func (c OAuth2CallbackResponse) GetProfilePicture() string {
	return c.Claims[CLAIM_PROFILE_PICTURE]
}

func (c OAuth2CallbackResponse) GetLocale() string {
	return c.Claims[CLAIM_LOCALE]
}

func (c OAuth2CallbackResponse) GetVerifiedEmail() bool {
	verifiedEmail := c.Claims[CLAIM_VERIFIED_EMAIL]
	if verifiedEmail == "" {
		return false
	}

	if r, err := strconv.ParseBool(verifiedEmail); err != nil {
		return false
	} else {
		return r
	}
}

type Oauth2CallbackState uint

const (
	OpenIdCallbackStateLoggedIn Oauth2CallbackState = iota
	OpenIdCallbackStateLoggedOut
)
