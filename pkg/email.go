// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import (
	_ "embed"
	"github.com/mattevans/postmark-go"
	"github.com/spf13/viper"
	"net/http"
)

// PostmarkClient defines our Postmark email client.
var PostmarkClient *postmark.Client

// init initializes our Postmark client.
func init() {
	if !viper.IsSet("postmark_token") {
		Logger.Fatal("unset postmark_token configuration variable")
	}

	PostmarkClient = postmark.NewClient(&http.Client{
		Transport: &postmark.AuthTransport{Token: viper.GetString("postmark_token")},
	})
}
