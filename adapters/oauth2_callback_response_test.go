package adapters

import "testing"

func TestOAuth2CallbackResponse_GetName(t *testing.T) {
	tests := []struct {
		name string
		c    OAuth2CallbackResponse
		want string
	}{
		{
			"name exists",
			OAuth2CallbackResponse{
				Claims: map[string]string{
					CLAIM_NAME: "joe",
				},
			},
			"joe",
		},
		{
			"name does not exist, but given name does",
			OAuth2CallbackResponse{
				Claims: map[string]string{
					CLAIM_GIVEN_NAME: "joe",
				},
			},
			"joe",
		},
		{
			"name does not exist, but given name and family name does",
			OAuth2CallbackResponse{
				Claims: map[string]string{
					CLAIM_GIVEN_NAME:  "joe",
					CLAIM_FAMILY_NAME: "doe",
				},
			},
			"joe doe",
		},
		{
			"name does not exist, but family name does",
			OAuth2CallbackResponse{
				Claims: map[string]string{
					CLAIM_FAMILY_NAME: "doe",
				},
			},
			"doe",
		},
		{
			"name does not exist, neither any of the other ones",
			OAuth2CallbackResponse{
				Claims: map[string]string{},
			},
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.GetName(); got != tt.want {
				t.Errorf("OAuth2CallbackResponse.GetName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOAuth2CallbackResponse_GetEmail(t *testing.T) {
	tests := []struct {
		name string
		c    OAuth2CallbackResponse
		want string
	}{
		{
			"email exists",
			OAuth2CallbackResponse{
				Claims: map[string]string{
					CLAIM_EMAIL: "joe@example.com",
				},
			},
			"joe@example.com",
		},
		{
			"email does not exist",
			OAuth2CallbackResponse{
				Claims: map[string]string{},
			},
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.GetEmail(); got != tt.want {
				t.Errorf("OAuth2CallbackResponse.GetEmail() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOAuth2CallbackResponse_GetUsername(t *testing.T) {
	tests := []struct {
		name string
		c    OAuth2CallbackResponse
		want string
	}{
		{
			"username exists",
			OAuth2CallbackResponse{
				Claims: map[string]string{
					CLAIM_EMAIL:    "joe@example.com",
					CLAIM_USERNAME: "joe",
				},
			},
			"joe",
		},
		{
			"username does not exists but email exists",
			OAuth2CallbackResponse{
				Claims: map[string]string{
					CLAIM_EMAIL: "joe@example.com",
				},
			},
			"joe@example.com",
		},
		{
			"username does not exist",
			OAuth2CallbackResponse{
				Claims: map[string]string{},
			},
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.GetUsername(); got != tt.want {
				t.Errorf("OAuth2CallbackResponse.GetUsername() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOAuth2CallbackResponse_GetFamilyName(t *testing.T) {
	tests := []struct {
		name string
		c    OAuth2CallbackResponse
		want string
	}{
		{
			"family name exists",
			OAuth2CallbackResponse{
				Claims: map[string]string{
					CLAIM_FAMILY_NAME: "doe",
				},
			},
			"doe",
		},
		{
			"family name does not exist",
			OAuth2CallbackResponse{
				Claims: map[string]string{},
			},
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.GetFamilyName(); got != tt.want {
				t.Errorf("OAuth2CallbackResponse.GetFamilyName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOAuth2CallbackResponse_GetGivenName(t *testing.T) {
	tests := []struct {
		name string
		c    OAuth2CallbackResponse
		want string
	}{
		{
			"given name exists",
			OAuth2CallbackResponse{
				Claims: map[string]string{
					CLAIM_GIVEN_NAME: "joe",
				},
			},
			"joe",
		},
		{
			"given name does not exist",
			OAuth2CallbackResponse{
				Claims: map[string]string{},
			},
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.GetGivenName(); got != tt.want {
				t.Errorf("OAuth2CallbackResponse.GetGivenName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOAuth2CallbackResponse_GetProfilePicture(t *testing.T) {
	tests := []struct {
		name string
		c    OAuth2CallbackResponse
		want string
	}{
		{
			"profile picture exists",
			OAuth2CallbackResponse{
				Claims: map[string]string{
					CLAIM_PROFILE_PICTURE: "http://profile",
				},
			},
			"http://profile",
		},
		{
			"profile picture does not exist",
			OAuth2CallbackResponse{
				Claims: map[string]string{},
			},
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.GetProfilePicture(); got != tt.want {
				t.Errorf("OAuth2CallbackResponse.GetProfilePicture() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOAuth2CallbackResponse_GetLocale(t *testing.T) {
	tests := []struct {
		name string
		c    OAuth2CallbackResponse
		want string
	}{
		{
			"locale exists",
			OAuth2CallbackResponse{
				Claims: map[string]string{
					CLAIM_LOCALE: "en",
				},
			},
			"en",
		},
		{
			"locale does not exist",
			OAuth2CallbackResponse{
				Claims: map[string]string{},
			},
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.GetLocale(); got != tt.want {
				t.Errorf("OAuth2CallbackResponse.GetLocale() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOAuth2CallbackResponse_GetVerifiedEmail(t *testing.T) {
	tests := []struct {
		name string
		c    OAuth2CallbackResponse
		want bool
	}{
		{
			"verified email exists and false",
			OAuth2CallbackResponse{
				Claims: map[string]string{
					CLAIM_VERIFIED_EMAIL: "false",
				},
			},
			false,
		},
		{
			"verified email exists and true",
			OAuth2CallbackResponse{
				Claims: map[string]string{
					CLAIM_VERIFIED_EMAIL: "true",
				},
			},
			true,
		},
		{
			"verified email exists but invalid",
			OAuth2CallbackResponse{
				Claims: map[string]string{
					CLAIM_VERIFIED_EMAIL: "something",
				},
			},
			false,
		},
		{
			"verified email does not exist",
			OAuth2CallbackResponse{
				Claims: map[string]string{},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.GetVerifiedEmail(); got != tt.want {
				t.Errorf("OAuth2CallbackResponse.GetVerifiedEmail() = %v, want %v", got, tt.want)
			}
		})
	}
}
