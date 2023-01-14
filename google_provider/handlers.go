package google_provider

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/cjlapao/common-go-identity-oauth2/adapters"
	openid "github.com/cjlapao/common-go-identity-oauth2/helpers"
	"github.com/cjlapao/common-go-restapi/controllers"
)

func (c *GoogleOauth2Client) Login() controllers.Controller {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			c.callbackRedirectUrl.SetTls()
		}

		c.config.RedirectURL = c.callbackRedirectUrl.Get()

		// Creating the cookie for use with google
		oauthState := openid.GenerateStateOauthCookie(c, c.tokenExpiration, w)

		// Calling google and setting the cookie
		u := c.config.AuthCodeURL(oauthState)

		// redirecting back to the application
		http.Redirect(w, r, u, http.StatusTemporaryRedirect)
	}
}

func (c *GoogleOauth2Client) Logout() controllers.Controller {
	return func(w http.ResponseWriter, r *http.Request) {
	}
}

func (c *GoogleOauth2Client) Callback() controllers.Controller {
	return func(w http.ResponseWriter, r *http.Request) {
		// Read oauthState from Cookie
		oauthState, err := r.Cookie(openid.GetCookieName(c))
		if err != nil {
			logger.Exception(err, "error getting cookie %s", openid.GetCookieName(c))
			if c.ErrorCallback != nil {
				response := adapters.OAuth2CallbackResponse{
					State:   adapters.OpenIdCallbackStateLoggedIn,
					Success: false,
					Error:   err,
				}
				c.ErrorCallback(&response)
			}

			if c.RedirectOnError {
				http.Redirect(w, r, c.errorRedirectPath, http.StatusTemporaryRedirect)
			}

			return
		}

		if r.FormValue("state") != oauthState.Value {
			logger.Error("Invalid oauth %s state", GOOGLE_DEFAULT_CLIENT_NAME)
			if c.ErrorCallback != nil {
				response := adapters.OAuth2CallbackResponse{
					State:   adapters.OpenIdCallbackStateLoggedIn,
					Success: false,
					Error:   err,
				}
				c.ErrorCallback(&response)
			}

			if c.RedirectOnError {
				http.Redirect(w, r, c.errorRedirectPath, http.StatusTemporaryRedirect)
			}
			return
		}

		data, err := getUserData(c, r.FormValue("code"))
		if err != nil {
			logger.Exception(err, "There was an error getting the user profile from %s", GOOGLE_DEFAULT_CLIENT_NAME)

			if c.ErrorCallback != nil {
				response := adapters.OAuth2CallbackResponse{
					State:   adapters.OpenIdCallbackStateLoggedIn,
					Success: false,
					Error:   err,
				}
				c.ErrorCallback(&response)
			}

			if c.RedirectOnError {
				http.Redirect(w, r, c.errorRedirectPath, http.StatusTemporaryRedirect)
			}

			return
		}

		if c.LoggedInCallback != nil {
			var userInfo map[string]interface{}
			err := json.Unmarshal(data, &userInfo)
			if err != nil {
				logger.Exception(err, "Error decoding user profile from %s", GOOGLE_DEFAULT_CLIENT_NAME)
				if c.ErrorCallback != nil {
					response := adapters.OAuth2CallbackResponse{
						State:   adapters.OpenIdCallbackStateLoggedIn,
						Success: false,
						Error:   err,
					}
					c.ErrorCallback(&response)
				}

				if c.RedirectOnError {
					http.Redirect(w, r, c.errorRedirectPath, http.StatusTemporaryRedirect)
				}

				return
			}

			fmt.Println(userInfo)
			response := adapters.OAuth2CallbackResponse{
				Success:       true,
				Claims:        make(map[string]string),
				Code:          r.FormValue("code"),
				CallbackState: r.FormValue("state"),
				State:         adapters.OpenIdCallbackStateLoggedIn,
			}

			response.Claims[adapters.CLAIM_EMAIL] = userInfo["email"].(string)
			response.Claims[adapters.CLAIM_USERNAME] = userInfo["email"].(string)
			response.Claims[adapters.CLAIM_FAMILY_NAME] = userInfo["family_name"].(string)
			response.Claims[adapters.CLAIM_GIVEN_NAME] = userInfo["given_name"].(string)
			response.Claims[adapters.CLAIM_NAME] = userInfo["name"].(string)
			response.Claims[adapters.CLAIM_PROFILE_PICTURE] = userInfo["picture"].(string)
			response.Claims[adapters.CLAIM_LOCALE] = userInfo["locale"].(string)
			response.Claims[adapters.CLAIM_VERIFIED_EMAIL] = strconv.FormatBool(userInfo["verified_email"].(bool))

			err = c.LoggedInCallback(&response)
			if err != nil {
				logger.Exception(err, "error on callback")
				if c.ErrorCallback != nil {
					response := adapters.OAuth2CallbackResponse{
						State:   adapters.OpenIdCallbackStateLoggedIn,
						Success: false,
						Error:   err,
					}
					c.ErrorCallback(&response)
				}

				if c.RedirectOnError {
					http.Redirect(w, r, c.errorRedirectPath, http.StatusTemporaryRedirect)
				}
			}
		}

		if c.RedirectOnSuccess {
			http.Redirect(w, r, c.loggedInRedirectPath, http.StatusTemporaryRedirect)
		}
	}
}
