// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import (
	_ "embed"
	"github.com/mattevans/postmark-go"
	"net/http"
	"os"
)

// PostmarkClient defines our Postmark email client.
var PostmarkClient *postmark.Client

// init initializes our Postmark client.
func init() {
	token := os.Getenv("POSTMARK_TOKEN")

	if token == "" {
		Logger.Fatalf("unset POSTMARK_TOKEN environment variable")
	}

	auth := &http.Client{
		Transport: &postmark.AuthTransport{Token: token},
	}

	PostmarkClient = postmark.NewClient(auth)
}
