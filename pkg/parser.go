// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import "github.com/jackc/pgx/v4"

// Parser is an interface for file parsers.
type Parser interface {
	GetName() string
	GetSupportedFileExtensions() []string
	Parse(evidence *Evidence, project Project, database *pgx.Conn) error
}

// GetParsers returns a list of all available parsers.
func GetParsers() []Parser {
	return []Parser{PSTParser{}, EMLParser{}}
}
