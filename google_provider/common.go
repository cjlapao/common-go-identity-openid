package google_provider

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

func getUserData(c *GoogleOauth2Client, code string) ([]byte, error) {
	// Use code to get token and get user info from Google.
	token, err := c.config.Exchange(context.Background(), code)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %s", err.Error())
	}
	u := fmt.Sprintf("%s?access_token=%s", GOOGLE_OAUTH_PROFILE_API_URL, token.AccessToken)
	response, err := http.Get(u)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}

	defer response.Body.Close()
	contents, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed read response: %s", err.Error())
	}

	return contents, nil
}
