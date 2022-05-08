// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import "github.com/spf13/viper"

var GoForensicsAPIURL string

// init initializes our configuration.
func init() {
	viper.SetConfigName("goforensics")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

	err := viper.ReadInConfig()

	if err != nil {
		Logger.Fatalf("Failed to initialize configuration file: %s", err)
	}

	if viper.IsSet("go_forensics_api_url") {
		GoForensicsAPIURL = viper.GetString("go_forensics_api_url")
	} else {
		Logger.Fatal("unset go_forensics_api_url configuration variable")
	}
}
