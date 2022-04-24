// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import (
	"errors"
)

// Bookmark represents a bookmarked message.
type Bookmark struct {
	MessageUUID string `json:"message_uuid"`
}

// Save saves the bookmark to the database.
func (bookmark *Bookmark) Save(project Project) error {
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

	statement, err := database.Prepare("INSERT OR REPLACE INTO bookmarks(messageUUID) VALUES (?)")

	if err != nil {
		return err
	}

	_, err = statement.Exec(bookmark.MessageUUID)

	if err != nil {
		return err
	}

	return nil
}

// GetBookmark returns the bookmark from the specified message UUID.
func GetBookmark(messageUUID string, project Project) (Bookmark, error) {
	database, err := GetProjectDatabase(project)

	if err != nil {
		return Bookmark{}, err
	}

	defer func() {
		err = database.Close()

		if err != nil {
			Logger.Errorf("Failed to close database: %s", err)
		}
	}()

	rows, err := database.Query("SELECT * FROM bookmarks WHERE messageUUID = ?", messageUUID)

	if err != nil {
		return Bookmark{}, err
	}

	var bookmark Bookmark

	for rows.Next() {
		err := rows.Scan(&bookmark.MessageUUID)

		if err != nil {
			return Bookmark{}, err
		}
	}

	if bookmark.MessageUUID == "" {
		return Bookmark{}, errors.New("failed to find bookmark")
	}

	return bookmark, nil
}

// DeleteBookmark deletes the bookmark from the specified message UUID.
func DeleteBookmark(messageUUID string, project Project) error {
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

	statement, err := database.Prepare("DELETE FROM bookmarks WHERE messageUUID = ?")

	if err != nil {
		return err
	}

	_, err = statement.Exec(messageUUID)

	if err != nil {
		return err
	}

	return nil
}

// GetBookmarksByProject returns all bookmarks for the specified project.
func GetBookmarksByProject(project Project) ([]Bookmark, error) {
	database, err := GetProjectDatabase(project)

	if err != nil {
		return nil, err
	}

	defer func() {
		err = database.Close()

		if err != nil {
			Logger.Errorf("Failed to close database: %s", err)
		}
	}()

	rows, err := database.Query("SELECT * FROM bookmarks")

	if err != nil {
		return nil, err
	}

	var bookmarks []Bookmark
	var bookmark Bookmark

	for rows.Next() {
		err := rows.Scan(&bookmark.MessageUUID)

		if err != nil {
			return nil, err
		}

		bookmarks = append(bookmarks, bookmark)
	}

	return bookmarks, nil
}
