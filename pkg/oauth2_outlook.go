// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net/http"
	"net/url"
)

// Variables defining our Microsoft OAuth2 credentials.
var (
	MicrosoftClientID     string
	MicrosoftClientSecret string
)

func init() {
	microsoftConfigurationVariables := []string{"microsoft_client_id", "microsoft_client_secret"}

	for _, configurationVariable := range microsoftConfigurationVariables {
		if !viper.IsSet(configurationVariable) {
			Logger.Fatalf("unset %s configuration variable", configurationVariable)
		}
	}

	MicrosoftClientID = viper.GetString("microsoft_client_id")
	MicrosoftClientSecret = viper.GetString("microsoft_client_secret")
}

var OutlookOAuth2Config = &oauth2.Config{
	ClientID:     MicrosoftClientID,
	ClientSecret: MicrosoftClientSecret,
	RedirectURL:  fmt.Sprintf("%s/outlook/emails/callback", GoForensicsAPIURL),
	Scopes: []string{
		"offline_access",
		"https://outlook.office.com/User.Read",
		"https://outlook.office.com/IMAP.AccessAsUser.All",
	},
	Endpoint: oauth2.Endpoint{
		AuthURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
	},
}

var OutlookUserProfileOAuth2Config = &oauth2.Config{
	ClientID:     MicrosoftClientID,
	ClientSecret: MicrosoftClientSecret,
	RedirectURL:  fmt.Sprintf("%s/outlook/profile/callback", GoForensicsAPIURL),
	Scopes: []string{
		"User.Read",
		"https://graph.microsoft.com/User.Read",
	},
	Endpoint: oauth2.Endpoint{
		AuthURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
	},
}

// GetOutlookEmailsAuthURL returns the authentication URL to Outlook (emails).
func GetOutlookEmailsAuthURL() string {
	return OutlookOAuth2Config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
}

// GetOutlookUserProfileAuthURL returns the authentication URL to Outlook (profile).
func GetOutlookUserProfileAuthURL() string {
	return OutlookUserProfileOAuth2Config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
}

// GetOutlookEmailsAccessToken exchange the authorization code for an access token.
func GetOutlookEmailsAccessToken(request *http.Request) (string, error) {
	queryParts, err := url.ParseQuery(request.URL.RawQuery)

	if err != nil {
		return "", err
	}

	code := queryParts["code"][0]

	token, err := OutlookOAuth2Config.Exchange(context.Background(), code)

	if err != nil {
		return "", err
	}

	return token.AccessToken, nil
}

// GetOutlookUserProfileAccessToken exchange the authorization code for an access token.
func GetOutlookUserProfileAccessToken(request *http.Request) (string, error) {
	queryParts, err := url.ParseQuery(request.URL.RawQuery)

	if err != nil {
		return "", err
	}

	code := queryParts["code"][0]

	token, err := OutlookUserProfileOAuth2Config.Exchange(context.Background(), code)

	if err != nil {
		return "", err
	}

	return token.AccessToken, nil
}

// GetOutlookUserProfile returns the user email.
func GetOutlookUserProfile(token string) (string, error) {
	request, err := http.NewRequest("GET", "https://graph.microsoft.com/v1.0/me", nil)

	request.Header.Add("Authorization", "Bearer "+token)

	response, err := http.DefaultClient.Do(request)

	if err != nil {
		return "", err
	}

	defer func() {
		err := response.Body.Close()

		if err != nil {
			Logger.Errorf("Failed to close response body: %s", err)
		}
	}()

	body, err := ioutil.ReadAll(response.Body)

	if err != nil {
		return "", err
	}

	var responseMap map[string]interface{}

	if err := json.Unmarshal(body, &responseMap); err != nil {
		return "", err
	}

	Logger.Infof("Response map: %s", responseMap)

	return responseMap["userPrincipalName"].(string), nil
}
