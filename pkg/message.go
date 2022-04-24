// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/aquasecurity/esquery"
	"io"
	"strings"
)

// Message represents a message.
type Message struct {
	UUID         string       `json:"uuid"`
	UserUUID     string       `json:"user_uuid"`
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
	FolderUUID   string       `json:"folder_uuid"`
	EvidenceUUID string       `json:"evidence_uuid"`
}

// JSON returns the JSON representation of this message.
func (message *Message) JSON() string {
	initializeEmptyMessageValues(message)

	var outputString strings.Builder

	if err := json.NewEncoder(&outputString).Encode(message); err != nil {
		Logger.Errorf("Failed to encode message.")
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
func GetMessagesFromQuery(query string, project Project) ([]Message, error) {
	var shouldMatch []esquery.Mappable

	for _, field := range AllMessageFields {
		shouldMatch = append(shouldMatch, esquery.Match(field, query))
	}

	response, err := esquery.Search().
		Query(
			esquery.
				Bool().
				Must(esquery.Term("user_uuid", project.UserUUID)).
				Must(esquery.Term("project_uuid", project.UUID)).
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

	return getMessagesFromSearchResult(response.Body)
}

// GetMessagesFromFolders returns the messages in the specified folders.
// isMessageContents may be true to only return the contents of the message (used when selecting a folder).
func GetMessagesFromFolders(folderUUIDs []string, project Project) ([]Message, error) {
	var shouldTerms []esquery.Mappable

	for _, folderUUID := range folderUUIDs {
		shouldTerms = append(shouldTerms, esquery.Term("folder_uuid", folderUUID))
	}

	response, err := esquery.Search().
		Query(
			esquery.
				Bool().
				Must(esquery.Term("user_uuid", project.UserUUID)).
				Must(esquery.Term("project_uuid", project.UUID)).
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

	return getMessagesFromSearchResult(response.Body)
}

// GetMessageByUUID returns the message with the specified UUID.
func GetMessageByUUID(messageUUID string, project Project) (Message, error) {
	response, err := esquery.Search().
		Query(
			esquery.
				Bool().
				Must(esquery.Term("user_uuid", project.UserUUID)).
				Must(esquery.Term("project_uuid", project.UUID)).
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

	messages, err := getMessagesFromSearchResult(response.Body)

	if err != nil {
		return Message{}, err
	}

	if len(messages) > 0 {
		return messages[0], nil
	}

	return Message{}, errors.New("failed to find message")
}

// GetAllMessages returns a list of all messages from the specified project.
func GetAllMessages(project Project) ([]Message, error) {
	response, err := esquery.Search().
		Query(
			esquery.
				Bool().
				Must(esquery.Term("user_uuid", project.UserUUID)).
				Must(esquery.Term("project_uuid", project.UUID)),
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

	return getMessagesFromSearchResult(response.Body)
}

// GetMessagesFromField returns all messages from the specified query and field.
func GetMessagesFromField(query string, field string, project Project) ([]Message, error) {
	response, err := esquery.Search().
		Query(
			esquery.
				Bool().
				Must(esquery.Term("user_uuid", project.UserUUID)).
				Must(esquery.Term("project_uuid", project.UUID)).
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

	return getMessagesFromSearchResult(response.Body)
}

// getMessagesFromSearchResult returns the messages from the search response.
func getMessagesFromSearchResult(responseBody io.ReadCloser) ([]Message, error) {
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
		hitFields := hit.(map[string]interface{})["_source"].(map[string]interface{})

		uuid := hitFields["uuid"].(string)

		userUUID, ok := hitFields["user_uuid"].(string)

		if !ok {
			Logger.Errorf("Failed to get user UUID from search result.")
			continue
		}

		projectUUID, ok := hitFields["project_uuid"].(string)

		if !ok {
			Logger.Errorf("Failed to get project UUID from search result.")
			continue
		}

		messageID, ok := hitFields["message_id"].(string)

		if !ok {
			messageID = ""
		}

		subject, ok := hitFields["subject"].(string)

		if !ok {
			subject = ""
		}

		from, ok := hitFields["from"].(string)

		if !ok {
			from = ""
		}

		to, ok := hitFields["to"].(string)

		if !ok {
			to = ""
		}

		cc, ok := hitFields["cc"].(string)

		if !ok {
			cc = ""
		}

		received, ok := hitFields["received"].(float64)

		if !ok {
			received = 0
		}

		size, ok := hitFields["size"].(string)

		if !ok {
			size = ""
		}

		body, ok := hitFields["body"].(string)

		if !ok {
			body = ""
		}

		headers, ok := hitFields["headers"].(string)

		if !ok {
			headers = ""
		}

		folderUUID, ok := hitFields["folder_uuid"].(string)

		if !ok {
			Logger.Errorf("Failed to get folderUUID field.")
		}

		evidenceUUID, ok := hitFields["evidence_uuid"].(string)

		if !ok {
			Logger.Errorf("Failed to get evidenceUUID field.")
		}

		var attachments []Attachment

		attachmentsMap, ok := hitFields["attachments"].([]interface{})

		if ok {
			attachmentsMapBytes, err := json.Marshal(attachmentsMap)

			if err != nil {
				Logger.Errorf("Failed to marshal attachments map: %s", err)
			}

			err = json.Unmarshal(attachmentsMapBytes, &attachments)

			if err != nil {
				Logger.Errorf("Failed to unmarshal attachments map: %s", err)
			}
		} else {
			if hitFields["attachments"] != nil {
				Logger.Errorf("Failed to convert attachments: %s", hitFields["attachments"].([]interface{}))
			}
		}

		messages = append(messages, Message{
			uuid,
			userUUID,
			projectUUID,
			messageID,
			subject,
			from,
			to,
			cc,
			int(received),
			size,
			body,
			headers,
			attachments,
			folderUUID,
			evidenceUUID,
		})
	}

	return messages, nil
}
