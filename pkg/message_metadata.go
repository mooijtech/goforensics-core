// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import (
	"context"
	"github.com/jackc/pgx/v4"
)

// MessageMetadata represents message metadata (isBookmarked, tag, comment).
type MessageMetadata struct {
	MessageUUID  string `json:"message_uuid"`
	ProjectUUID  string `json:"project_uuid"`
	IsBookmarked bool   `json:"is_bookmarked"`
	Tag          string `json:"tag"`
	Comment      string `json:"comment"`
}

// AddBookmark sets the message metadata isBookmark to true.
func AddBookmark(messageUUID string, projectUUID string, database *pgx.Conn) error {
	preparedStatement := `
	INSERT INTO message_metadata(messageUUID, projectUUID, isBookmarked, tag, comment) VALUES ($1, $2, $3, $4, $5) 
	ON CONFLICT(messageUUID) DO UPDATE SET isBookmarked = $3
	`
	_, err := database.Exec(context.Background(), preparedStatement, messageUUID, projectUUID, true, "", "")

	return err
}

// RemoveBookmark sets the message metadata isBookmark to false.
func RemoveBookmark(messageUUID string, projectUUID string, database *pgx.Conn) error {
	preparedStatement := `
	INSERT INTO message_metadata(messageUUID, projectUUID, isBookmarked, tag, comment) VALUES ($1, $2, $3, $4, $5) 
	ON CONFLICT(messageUUID) DO UPDATE SET isBookmarked = $3
	`
	_, err := database.Exec(context.Background(), preparedStatement, messageUUID, projectUUID, false, "", "")

	return err
}

// GetBookmarksByProject returns all bookmarks .
func GetBookmarksByProject(projectUUID string, database *pgx.Conn) ([]Message, error) {
	preparedStatement := `
	SELECT * FROM message_metadata WHERE projectUUID = $1
	`
	rows, err := database.Query(context.Background(), preparedStatement, projectUUID)

	if err != nil {
		return nil, err
	}

	var messages []Message

	for rows.Next() {
		var messageMetadata MessageMetadata

		err := rows.Scan(&messageMetadata.MessageUUID, &messageMetadata.ProjectUUID, &messageMetadata.IsBookmarked, &messageMetadata.Tag, &messageMetadata.Comment)

		if err != nil {
			return nil, err
		}

		if messageMetadata.IsBookmarked {
			message, err := GetMessageByUUID(messageMetadata.MessageUUID, projectUUID)

			if err != nil {
				return nil, err
			}

			messages = append(messages, message)
		}
	}

	rows.Close()

	return messages, rows.Err()
}

// AddTag sets the message metadata tag.
func AddTag(tag string, messageUUID string, projectUUID string, database *pgx.Conn) error {
	preparedStatement := `
	INSERT INTO message_metadata(messageUUID, projectUUID, isBookmarked, tag, comment) VALUES ($1, $2, $3, $4, $5) 
	ON CONFLICT(messageUUID) DO UPDATE SET tag = $4
	`
	_, err := database.Exec(context.Background(), preparedStatement, messageUUID, projectUUID, false, tag, "")

	return err
}

// RemoveTag removes the message metadata tag.
func RemoveTag(messageUUID string, projectUUID string, database *pgx.Conn) error {
	preparedStatement := `
	INSERT INTO message_metadata(messageUUID, projectUUID, isBookmarked, tag, comment) VALUES ($1, $2, $3, $4, $5) 
	ON CONFLICT(messageUUID) DO UPDATE SET tag = $4
	`
	_, err := database.Exec(context.Background(), preparedStatement, messageUUID, projectUUID, false, "", "")

	return err
}

// GetMessageMetadata returns the message metadata of the message.
func GetMessageMetadata(messageUUID string, projectUUID string, database *pgx.Conn) (MessageMetadata, error) {
	preparedStatement := `
	SELECT * FROM message_metadata WHERE messageUUID = $1 AND projectUUID = $2
	`
	row := database.QueryRow(context.Background(), preparedStatement, messageUUID, projectUUID)

	var messageMetadata MessageMetadata

	if err := row.Scan(&messageMetadata.MessageUUID, &messageMetadata.ProjectUUID, &messageMetadata.IsBookmarked, &messageMetadata.Tag, &messageMetadata.Comment); err != nil {
		return MessageMetadata{}, err
	}

	return messageMetadata, nil
}
