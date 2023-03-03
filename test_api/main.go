package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/cjlapao/common-go-identity-oauth2/adapters"
	"github.com/cjlapao/common-go-identity-oauth2/facebook_provider"
	"github.com/cjlapao/common-go-identity-oauth2/google_provider"
	"github.com/cjlapao/common-go-identity-oauth2/oauth2context"
	log "github.com/cjlapao/common-go-logger"
	restapi "github.com/cjlapao/common-go-restapi"
	"github.com/cjlapao/common-go-restapi/controllers"
	"github.com/cjlapao/common-go/execution_context"
)

var listener *restapi.HttpListener

func LoggedIn() controllers.Controller {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode("all good")
	}
}

func ErrorEndpoint() controllers.Controller {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode("All bad")
	}
}

func main() {
	logger := log.Get()
	ctx := execution_context.Get()
	ctx.WithDefaultAuthorization()
	listener = restapi.GetHttpListener()
	listener.AddJsonContent().AddLogger().AddHealthCheck()
	listener.AddController(LoggedIn(), "main", "GET")
	listener.AddController(ErrorEndpoint(), "error", "GET")

	openIdCtx := oauth2context.New(listener, oauth2context.NewOAuthContextOptions())
	openIdCtx.SuccessCallbackPath = "/main"
	openIdCtx.ErrorCallbackPath = "/err"
	openIdCtx.Options.BaseDomain = "localhost:5000"

	// Starting the google provider
	googleConfig := adapters.OAuth2ProviderOptions{
		ClientSecret:            ctx.Configuration.GetString("GOOGLE_CLIENT_SECRET"),
		ClientId:                ctx.Configuration.GetString("GOOGLE_CLIENT_ID"),
		LoggedInCallback:        GoogleCallBack,
		LoggedOutCallback:       GoogleCallBack,
		SuccessCallBackRedirect: true,
	}

	_, err := google_provider.Register(googleConfig)
	if err != nil {
		logger.Exception(err, "there was an error registering google provider")
	}

	// Starting the google provider
	facebookConfig := adapters.OAuth2ProviderOptions{
		ClientSecret:            ctx.Configuration.GetString("FACEBOOK_CLIENT_SECRET"),
		ClientId:                ctx.Configuration.GetString("FACEBOOK_CLIENT_ID"),
		LoggedInCallback:        FacebookCallBack,
		LoggedOutCallback:       FacebookCallBack,
		SuccessCallBackRedirect: true,
	}

	_, err = facebook_provider.Register(facebookConfig)
	if err != nil {
		logger.Exception(err, "there was an error registering facebook provider")
	}

	listener.Start()
}

func GoogleCallBack(data *adapters.OAuth2CallbackResponse) error {
	fmt.Println("Result of callback")
	if data.State == adapters.OpenIdCallbackStateLoggedIn {
		if data != nil {
			fmt.Printf("Google Login => Email: %s, Name: %s, Verified Email: %s\n", data.GetEmail(), data.GetName(), strconv.FormatBool(data.GetVerifiedEmail()))
		}

		return nil
	} else {
		fmt.Printf("logged out successfully\n")
		return nil
	}
}

func FacebookCallBack(data *adapters.OAuth2CallbackResponse) error {
	fmt.Println("Result of callback")
	if data.State == adapters.OpenIdCallbackStateLoggedIn {
		if data != nil {
			fmt.Printf("Facebook Login => Email: %s, Name: %s, Verified Email: %s\n", data.GetEmail(), data.GetName(), strconv.FormatBool(data.GetVerifiedEmail()))
		}

		return nil
	} else {
		fmt.Printf("logged out successfully\n")
		return nil
	}
}
