// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import (
	"context"
	"fmt"
	_ "github.com/emersion/go-message/charset"
	"github.com/emersion/go-message/mail"
	"github.com/jackc/pgx/v4"
	"github.com/segmentio/kafka-go"
	"golang.org/x/sync/errgroup"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// EMLParser handles parsing EML files using go-message.
type EMLParser struct {
	Parser
}

// GetName returns the name of this parser.
func (parser EMLParser) GetName() string {
	return "EML"
}

// GetSupportedFileExtensions returns the supported file extensions.
func (parser EMLParser) GetSupportedFileExtensions() []string {
	return []string{".zip"}
}

// Parse parses the PST file.
func (parser EMLParser) Parse(evidence *Evidence, project Project, database *pgx.Conn) error {
	errorGroup, _ := errgroup.WithContext(context.Background())

	errorGroup.Go(func() error {
		evidencePath, err := DownloadEvidence(*evidence, project.UUID)

		if err != nil {
			Logger.Errorf("Failed to download evidence: %s", err)
			return err
		}

		unzippedUUID := NewUUID()
		unzippedDirectory := fmt.Sprintf("%s/%s", GetProjectTempDirectory(project.UUID), unzippedUUID)

		err = os.Mkdir(unzippedDirectory, 0755)

		if err != nil {
			return err
		}

		defer func() {
			if err := os.Remove(evidencePath); err != nil {
				Logger.Errorf("Failed to cleanup evidence file: %s", err)
			}

			if err := os.RemoveAll(unzippedUUID); err != nil {
				Logger.Errorf("Failed to cleanup evidence: %s", err)
			}
		}()

		// Unzip the evidence.
		err = Unzip(evidencePath, unzippedDirectory)

		if err != nil {
			return err
		}

		// Create our root tree node for EML files.
		rootTreeNode := TreeNode{
			FolderUUID:   NewUUID(),
			ProjectUUID:  project.UUID,
			EvidenceUUID: evidence.UUID,
			Title:        strings.Split(evidence.FileName, "-")[1],
			Parent:       "NULL",
		}

		if err := rootTreeNode.Save(database); err != nil {
			Logger.Errorf("Failed to save tree node to database: %s", err)
			return err
		}

		// Walk the EML files.
		var kafkaMessages []kafka.Message

		err = filepath.WalkDir(unzippedDirectory, func(path string, entry fs.DirEntry, err error) error {
			if !entry.IsDir() {
				message, err := parseEMLFile(path, project, rootTreeNode)

				if err != nil {
					Logger.Errorf("Failed to parse EML file: %s", err)
					return nil
				}

				kafkaMessages = append(kafkaMessages, kafka.Message{
					Key:   []byte(message.UUID),
					Value: []byte(message.JSON()),
				})

				if len(kafkaMessages) > 100 {
					err := KafkaWriter.WriteMessages(context.Background(), kafkaMessages...)

					if err != nil {
						return err
					}

					kafkaMessages = []kafka.Message{}
				}
			}

			return nil
		})

		if err != nil {
			return err
		}

		if len(kafkaMessages) > 0 {
			err := KafkaWriter.WriteMessages(context.Background(), kafkaMessages...)

			if err != nil {
				return err
			}
		}

		return nil
	})

	return errorGroup.Wait()
}

// Taken from  https://github.com/sg3des/eml/blob/master/date.go
var dateFormats = []string{
	`Mon, 02 Jan 2006 15:04 -0700`,
	`02 Jan 2006 15:04 -0700`,
	`Mon, 02 Jan 2006 15:04:05 -0700`,
	`02 Jan 2006 15:04:05 -0700`,

	`Mon, 02 Jan 2006 15:04 -0700 (MST)`,
	`02 Jan 2006 15:04 -0700 (MST)`,
	`Mon, 02 Jan 2006 15:04:05 -0700 (MST)`,
	`02 Jan 2006 15:04:05 -0700 (MST)`,

	`Mon, 2 Jan 2006 15:04 -0700`,
	`2 Jan 2006 15:04 -0700`,
	`Mon, 2 Jan 2006 15:04:05 -0700`,
	`2 Jan 2006 15:04:05 -0700`,

	`Mon, 2 Jan 2006 15:04 -0700 (MST)`,
	`2 Jan 2006 15:04 -0700 (MST)`,
	`Mon, 2 Jan 2006 15:04:05 -0700 (MST)`,
	`2 Jan 2006 15:04:05 -0700 (MST)`,
}

// parseEMLFile parses the EML file.
func parseEMLFile(path string, project Project, rootTreeNode TreeNode) (Message, error) {
	inputFile, err := os.Open(path)

	if err != nil {
		return Message{}, err
	}

	defer func() {
		err := inputFile.Close()

		if err != nil {
			Logger.Errorf("Failed to close file: %s", err)
		}
	}()

	var message Message
	var headerBuilder strings.Builder
	var bodyBuilder strings.Builder
	var attachments []Attachment

	mailReader, err := mail.CreateReader(inputFile)

	if err != nil {
		return Message{}, err
	}

	fields := mailReader.Header.Fields()

	for fields.Next() {
		if fields.Key() == "Subject" {
			message.Subject = fields.Value()
		}
		if fields.Key() == "To" {
			message.To = fields.Value()
		}
		if fields.Key() == "From" {
			message.From = fields.Value()
		}
		if fields.Key() == "CC" {
			message.CC = fields.Value()
		}
		if fields.Key() == "Date" {
			foundDateFormat := false

			for _, dateFormat := range dateFormats {
				t, err := time.Parse(dateFormat, fields.Value())

				if err == nil {
					message.Received = int(t.Unix())
					foundDateFormat = true
					break
				}
			}

			if !foundDateFormat {
				Logger.Warnf("Failed to parse data format: %s", fields.Value())
				message.Received = 0
			}
		}

		headerBuilder.WriteString(fmt.Sprintf("%s: %s\n", fields.Key(), fields.Value()))
	}

	for {
		part, err := mailReader.NextPart()

		if err == io.EOF {
			break
		} else if err != nil {
			return Message{}, err
		}

		switch h := part.Header.(type) {
		case *mail.InlineHeader:
			contentDisposition, params, err := part.Header.(*mail.InlineHeader).ContentDisposition()

			if err != nil {
				continue
			}

			if contentDisposition == "inline" {
				// Attachment
				attachment := Attachment{
					UUID: NewUUID(),
					Name: params["filename"],
				}

				attachments = append(attachments, attachment)

				// Write the attachment to disk then upload it to MinIO.
				body, err := ioutil.ReadAll(part.Body)

				if err != nil {
					return Message{}, nil
				}

				err = ioutil.WriteFile(fmt.Sprintf("%s/%s", GetProjectTempDirectory(project.UUID), attachment.UUID), body, 0755)

				if err != nil {
					return Message{}, err
				}

				_, err = UploadFile(attachment.UUID, fmt.Sprintf("%s/%s", GetProjectTempDirectory(project.UUID), attachment.UUID), project.UUID)

				if err != nil {
					return Message{}, err
				}

				err = os.Remove(fmt.Sprintf("%s/%s", GetProjectTempDirectory(project.UUID), attachment.UUID))

				if err != nil {
					return Message{}, err
				}
			} else {
				body, err := ioutil.ReadAll(part.Body)

				if err != nil {
					return Message{}, nil
				}

				bodyBuilder.WriteString(string(body))
			}

			fields := part.Header.(*mail.InlineHeader).Fields()

			for fields.Next() {
				headerBuilder.WriteString(fmt.Sprintf("%s: %s", fields.Key(), fields.Value()))
			}
		case *mail.AttachmentHeader:
			fileName, err := h.Filename()

			if err != nil {
				Logger.Errorf("Failed to get filename.")
				continue
			}

			Logger.Infof("Attachment header: %s", fileName)
		}
	}

	message.UUID = NewUUID()
	message.ProjectUUID = project.UUID
	message.FolderUUID = rootTreeNode.FolderUUID
	message.Headers = headerBuilder.String()
	message.Body = bodyBuilder.String()
	message.Attachments = attachments

	return message, nil
}
