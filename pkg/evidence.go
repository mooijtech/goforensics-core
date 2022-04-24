// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import (
	"errors"
	"strings"
)

// Evidence represents a PST file.
type Evidence struct {
	UUID     string `json:"uuid"`
	FileHash string `json:"file_hash"`
	FileName string `json:"file_name"`
	IsParsed bool   `json:"is_parsed"`
}

// Save saves the evidence to the database.
func (evidence *Evidence) Save(project Project) error {
	database, err := GetProjectDatabase(project)

	if err != nil {
		return err
	}

	defer func() {
		err = database.Close()

		if err != nil {
			Logger.Errorf("Failed to close database: %s", err)
		}
	}()

	statement, err := database.Prepare("INSERT OR REPLACE INTO evidence(uuid, fileHash, fileName, isParsed) VALUES (?,?,?,?)")

	if err != nil {
		return err
	}

	_, err = statement.Exec(evidence.UUID, evidence.FileHash, evidence.FileName, evidence.IsParsed)

	if err != nil {
		return err
	}

	return nil
}

// Parse calls all supported parsers on the file.
func (evidence *Evidence) Parse(project Project) error {
	if evidence.IsParsed {
		return errors.New("evidence is already parsed")
	}

	foundParser := false

	for _, parser := range GetParsers() {
		supportsExtension := false

		for _, extension := range parser.GetSupportedFileExtensions() {
			if strings.HasSuffix(evidence.FileName, extension) {
				supportsExtension = true
				foundParser = true
				break
			}
		}

		if supportsExtension {
			err := parser.Parse(evidence, project)

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
