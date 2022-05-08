// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/aquasecurity/esquery"
	"github.com/jackc/pgx/v4"
	"io"
	"strings"
)

// Message represents a message.
type Message struct {
	UUID         string       `json:"uuid"`
	ProjectUUID  string       `json:"project_uuid"`
	MessageID    string       `json:"message_id"`
	Subject      string       `json:"subject"`
	From         string       `json:"from"`
	To           string       `json:"to"`
	CC           string       `json:"cc"`
	Received     int          `json:"received"`
	Size         string       `json:"size"`
	Body         string       `json:"body"`
	Headers      string       `json:"headers"`
	Attachments  []Attachment `json:"attachments"`
	IsBookmarked bool         `json:"is_bookmarked,omitempty"`
	Tag          string       `json:"tag,omitempty"`
	Comment      string       `json:"comment,omitempty"`
	FolderUUID   string       `json:"folder_uuid"`
	EvidenceUUID string       `json:"evidence_uuid"`
}

// JSON returns the JSON representation of this message.
func (message *Message) JSON() string {
	initializeEmptyMessageValues(message)

	var outputString strings.Builder

	if err := json.NewEncoder(&outputString).Encode(message); err != nil {
		Logger.Errorf("Failed to encode message: %s", err)
		return ""
	}

	return outputString.String()
}

// messageNullValue defines the null_value used by Elasticsearch.
const messageNullValue = "NULL"

// initializeEmptyMessageValues initializes all empty values to Elasticsearch null_value.
// vector.dev does not like empty values.
func initializeEmptyMessageValues(message *Message) {
	if strings.TrimSpace(message.MessageID) == "" {
		message.MessageID = messageNullValue
	}
	if strings.TrimSpace(message.Subject) == "" {
		message.Subject = messageNullValue
	}
	if strings.TrimSpace(message.From) == "" {
		message.From = messageNullValue
	}
	if strings.TrimSpace(message.To) == "" {
		message.To = messageNullValue
	}
	if strings.TrimSpace(message.CC) == "" {
		message.CC = messageNullValue
	}
	if strings.TrimSpace(message.Size) == "" {
		message.Size = messageNullValue
	}
	if strings.TrimSpace(message.Body) == "" {
		message.Body = messageNullValue
	}
	if strings.TrimSpace(message.Headers) == "" {
		message.Headers = messageNullValue
	}
}

// AllMessageFields defines the message fields.
var (
	AllMessageFields = []string{"subject", "from", "to", "cc", "body", "headers", "attachments.name"}
)

// GetMessagesFromQuery returns all messages from the specified search query.
func GetMessagesFromQuery(query string, projectUUID string, database *pgx.Conn) ([]Message, error) {
	var shouldMatch []esquery.Mappable

	for _, field := range AllMessageFields {
		shouldMatch = append(shouldMatch, esquery.Match(field, query))
	}

	response, err := esquery.Search().
		Query(
			esquery.
				Bool().
				Must(esquery.Term("project_uuid", projectUUID)).
				MinimumShouldMatch(1).
				Should(shouldMatch...),
		).
		Size(10000).
		Run(
			Elasticsearch,
			Elasticsearch.Search.WithContext(context.Background()),
			Elasticsearch.Search.WithIndex("messages"),
		)

	if err != nil {
		return nil, err
	}

	return getMessagesFromSearchResult(response.Body, database)
}

// GetMessagesFromFolders returns the messages in the specified folders.
func GetMessagesFromFolders(folderUUIDs []string, projectUUID string, database *pgx.Conn) ([]Message, error) {
	var shouldTerms []esquery.Mappable

	for _, folderUUID := range folderUUIDs {
		shouldTerms = append(shouldTerms, esquery.Term("folder_uuid", folderUUID))
	}

	response, err := esquery.Search().
		Query(
			esquery.
				Bool().
				Must(esquery.Term("project_uuid", projectUUID)).
				MinimumShouldMatch(1).
				Should(shouldTerms...),
		).
		Size(10000).
		Run(
			Elasticsearch,
			Elasticsearch.Search.WithContext(context.Background()),
			Elasticsearch.Search.WithIndex("messages"),
		)

	if err != nil {
		return nil, err
	}

	return getMessagesFromSearchResult(response.Body, database)
}

// GetMessageByUUID returns the message with the specified UUID.
func GetMessageByUUID(messageUUID string, projectUUID string, database *pgx.Conn) (Message, error) {
	response, err := esquery.Search().
		Query(
			esquery.
				Bool().
				Must(esquery.Term("project_uuid", projectUUID)).
				Must(esquery.Term("uuid", messageUUID)),
		).
		Size(1).
		Run(
			Elasticsearch,
			Elasticsearch.Search.WithContext(context.Background()),
			Elasticsearch.Search.WithIndex("messages"),
		)

	if err != nil {
		return Message{}, err
	}

	messages, err := getMessagesFromSearchResult(response.Body, database)

	if err != nil {
		return Message{}, err
	}

	if len(messages) > 0 {
		return messages[0], nil
	}

	return Message{}, errors.New("failed to find message")
}

// GetAllMessages returns a list of all messages from the specified project.
func GetAllMessages(projectUUID string, database *pgx.Conn) ([]Message, error) {
	response, err := esquery.Search().
		Query(
			esquery.
				Bool().
				Must(esquery.Term("project_uuid", projectUUID)),
		).
		Size(10000).
		Run(
			Elasticsearch,
			Elasticsearch.Search.WithContext(context.Background()),
			Elasticsearch.Search.WithIndex("messages"),
		)

	if err != nil {
		return nil, err
	}

	return getMessagesFromSearchResult(response.Body, database)
}

// GetMessagesFromField returns all messages from the specified query and field.
func GetMessagesFromField(query string, field string, projectUUID string, database *pgx.Conn) ([]Message, error) {
	response, err := esquery.Search().
		Query(
			esquery.
				Bool().
				Must(esquery.Term("project_uuid", projectUUID)).
				Must(esquery.Match(field, query)),
		).
		Size(10000).
		Run(
			Elasticsearch,
			Elasticsearch.Search.WithContext(context.Background()),
			Elasticsearch.Search.WithIndex("messages"),
		)

	if err != nil {
		return nil, err
	}

	return getMessagesFromSearchResult(response.Body, database)
}

// getMessagesFromSearchResult returns the messages from the search response.
func getMessagesFromSearchResult(responseBody io.ReadCloser, database *pgx.Conn) ([]Message, error) {
	var responseMap map[string]interface{}

	if err := json.NewDecoder(responseBody).Decode(&responseMap); err != nil {
		return nil, err
	}

	defer func() {
		err := responseBody.Close()

		if err != nil {
			Logger.Errorf("Failed to close Elasticsearch response: %s", err)
		}
	}()

	var messages []Message

	for _, hit := range responseMap["hits"].(map[string]interface{})["hits"].([]interface{}) {
		var message Message

		hitFields := hit.(map[string]interface{})["_source"].(map[string]interface{})
		hitBytes, err := json.Marshal(hitFields)

		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(hitBytes, &message)

		if err != nil {
			return nil, err
		}

		messageMetadata, err := GetMessageMetadata(message.UUID, message.ProjectUUID, database)

		if err == nil {
			message.IsBookmarked = messageMetadata.IsBookmarked
			message.Tag = messageMetadata.Tag
			message.Comment = messageMetadata.Comment
		} else if err == pgx.ErrNoRows {
			// No message metadata.
		} else {
			Logger.Errorf("Failed to get message metadata: %s", err)
		}

		messages = append(messages, message)
	}

	return messages, nil
}
