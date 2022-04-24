// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import "github.com/segmentio/ksuid"

// NewUUID creates a database friendly UUID.
func NewUUID() string {
	uuid, err := ksuid.NewRandom()

	if err != nil {
		Logger.Fatal("Failed to create UUID: %s", err)
	}

	return uuid.String()
}
