// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import "errors"

// Attachment represents an attachment.
type Attachment struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

// GetAllAttachments returns all attachments from all messages.
func GetAllAttachments(projectUUID string) ([]Attachment, error) {
	// TODO - Implement this.
	return nil, errors.New("not implemented yet")
}
