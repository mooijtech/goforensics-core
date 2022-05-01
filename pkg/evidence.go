// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v4"
	"path/filepath"
)

// Evidence represents a PST file.
type Evidence struct {
	UUID     string `json:"uuid"`
	FileHash string `json:"file_hash"`
	FileName string `json:"file_name"`
	IsParsed bool   `json:"is_parsed"`
}

// Save saves the evidence to the database.
// To assign the evidence to a project call AddProjectEvidence.
func (evidence *Evidence) Save(database *pgx.Conn) error {
	preparedStatement := `
	INSERT INTO evidence(uuid, fileHash, fileName, isParsed) VALUES ($1, $2, $3, $4)
	ON CONFLICT(uuid) DO UPDATE SET isParsed = $4
	`
	if _, err := database.Exec(context.Background(), preparedStatement, evidence.UUID, evidence.FileHash, evidence.FileName, evidence.IsParsed); err != nil {
		return err
	}

	return nil
}

// Parse calls all supported parsers on the file.
func (evidence *Evidence) Parse(project Project, database *pgx.Conn) error {
	if evidence.IsParsed {
		return errors.New("evidence is already parsed")
	}

	foundParser := false

	for _, parser := range GetParsers() {
		supportsExtension := false

		for _, extension := range parser.GetSupportedFileExtensions() {
			if filepath.Ext(evidence.FileName) == extension {
				supportsExtension = true
				foundParser = true
				break
			}
		}

		if supportsExtension {
			err := parser.Parse(evidence, project, database)

			if err != nil {
				return err
			}
		}
	}

	if !foundParser {
		return errors.New("failed to find supported parser")
	}

	return nil
}
