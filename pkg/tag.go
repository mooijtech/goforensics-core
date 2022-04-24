// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import (
	"errors"
)

// Tag represents a tagged message.
type Tag struct {
	MessageUUID string `json:"message_uuid"`
	Tag         string `json:"tag"`
}

// Save saves the tag to the database.
func (tag *Tag) Save(project Project) error {
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

	statement, err := database.Prepare("INSERT OR REPLACE INTO tags(messageUUID, tag) VALUES (?,?)")

	if err != nil {
		return err
	}

	_, err = statement.Exec(tag.MessageUUID, tag.Tag)

	if err != nil {
		return err
	}

	return nil
}

// GetTag returns the tag of the message specified.
func GetTag(messageUUID string, project Project) (Tag, error) {
	database, err := GetProjectDatabase(project)

	if err != nil {
		return Tag{}, err
	}

	defer func() {
		err = database.Close()

		if err != nil {
			Logger.Errorf("Failed to close database: %s", err)
		}
	}()

	rows, err := database.Query("SELECT * FROM tags WHERE messageUUID = ?", messageUUID)

	if err != nil {
		return Tag{}, err
	}

	var tag Tag

	for rows.Next() {
		err := rows.Scan(&tag.MessageUUID, &tag.Tag)

		if err != nil {
			return Tag{}, err
		}
	}

	if tag.MessageUUID == "" {
		return Tag{}, errors.New("failed to find tag")
	}

	return tag, nil
}

// DeleteTag returns the tag from the specified message UUID.
func DeleteTag(messageUUID string, project Project) error {
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

	statement, err := database.Prepare("DELETE FROM tags WHERE messageUUID = ?")

	if err != nil {
		return err
	}

	_, err = statement.Exec(messageUUID)

	if err != nil {
		return err
	}

	return nil
}
