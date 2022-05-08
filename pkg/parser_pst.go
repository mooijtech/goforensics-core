// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v4"
	"github.com/mooijtech/go-pst/v4/pkg"
	"github.com/segmentio/kafka-go"
	"golang.org/x/sync/errgroup"
	"os"
	"strings"
)

// PSTParser handles parsing PST files using go-pst.
type PSTParser struct {
	Parser
}

// GetName returns the name of this parser.
func (parser PSTParser) GetName() string {
	return "PST"
}

// GetSupportedFileExtensions returns the supported file extensions.
func (parser PSTParser) GetSupportedFileExtensions() []string {
	return []string{".pst"}
}

// Parse parses the PST file.
func (parser PSTParser) Parse(evidence *Evidence, project Project, database *pgx.Conn) error {
	errorGroup, _ := errgroup.WithContext(context.Background())

	errorGroup.Go(func() error {
		pstFile, err := pst.NewFromFile(fmt.Sprintf("data/%s/%s", MinIOBucketName, evidence.FileHash))

		if err != nil {
			Logger.Errorf("Failed to create new PST file: %s", err)
			return err
		}

		defer func() {
			err := pstFile.Close()

			if err != nil {
				Logger.Errorf("Failed to close PST file: %s", err)
			}
		}()

		Logger.Infof("Parsing file: %s...", evidence.FileHash)

		isValidSignature, err := pstFile.IsValidSignature()

		if err != nil {
			Logger.Errorf("Failed to read signature: %s", err)
			return errors.New("failed to read signature")
		}

		if !isValidSignature {
			Logger.Errorf("Invalid file signature.")
			return errors.New("invalid file signature")
		}

		contentType, err := pstFile.GetContentType()

		if err != nil {
			Logger.Errorf("Failed to get content type: %s", err)
			return errors.New("failed to get content type")
		}

		Logger.Infof("Content type: %s", contentType)

		formatType, err := pstFile.GetFormatType()

		if err != nil {
			Logger.Errorf("Failed to get format type: %s", err)
			return errors.New("failed to get format type")
		}

		Logger.Infof("Format type: %s", formatType)

		encryptionType, err := pstFile.GetEncryptionType(formatType)

		if err != nil {
			Logger.Errorf("Failed to get encryption type: %s", err)
			return errors.New("failed to get encryption type")
		}

		Logger.Infof("Encryption type: %s", encryptionType)
		Logger.Info("Initializing B-Trees...")

		err = pstFile.InitializeBTrees(formatType)

		if err != nil {
			Logger.Errorf("Failed to initialize node and block b-tree: %s", err)
			return errors.New("failed to initialize node and block b-tree")
		}

		err = pstFile.InitializeNameToIDMap(formatType, encryptionType)

		if err != nil {
			Logger.Errorf("Failed to initialize Name-To-ID Map: %s", err)
			return errors.New("failed to initialize Name-To-ID Map")
		}

		rootFolder, err := pstFile.GetRootFolder(formatType, encryptionType)

		if err != nil {
			Logger.Errorf("Failed to get root folder: %s", err)
			return errors.New("failed to get root folder")
		}

		rootTreeNode := TreeNode{
			FolderUUID:   NewUUID(),
			ProjectUUID:  project.UUID,
			EvidenceUUID: evidence.UUID,
			Title:        strings.Split(evidence.FileName, "-")[1],
			Parent:       "NULL",
		}

		err = rootTreeNode.Save(database)

		if err != nil {
			Logger.Errorf("Failed to save tree node: %s", err)
			return errors.New("failed to save tree node")
		}

		err = parseSubFolders(pstFile, rootFolder, formatType, encryptionType, project, evidence, database, rootTreeNode)

		if err != nil {
			Logger.Errorf("Failed to get sub-folders: %s", err)
			return errors.New("failed to get sub-folders")
		}

		evidence.IsParsed = true

		err = evidence.Save(database)

		if err != nil {
			Logger.Errorf("Failed to save evidence: %s", err)
			return err
		}

		Logger.Infof("Finished parsing file: %s", evidence.FileHash)

		return nil
	})

	return errorGroup.Wait()
}

// parseSubFolders is a recursive function which parses all sub-folders for the specified folder.
func parseSubFolders(pstFile pst.File, folder pst.Folder, formatType string, encryptionType string, project Project, evidence *Evidence, database *pgx.Conn, treeNode TreeNode) error {
	subFolders, err := pstFile.GetSubFolders(folder, formatType, encryptionType)

	if err != nil {
		return err
	}

	for _, subFolder := range subFolders {
		Logger.Infof("Parsing sub-folder: %s", subFolder.DisplayName)

		messages, err := pstFile.GetMessages(subFolder, formatType, encryptionType)

		if err != nil {
			return err
		}

		// Initialize our tree node (folders presented in the filesystem).
		subFolderTreeNode := TreeNode{
			FolderUUID:   NewUUID(),
			EvidenceUUID: evidence.UUID,
			Title:        subFolder.DisplayName,
			Parent:       treeNode.FolderUUID,
		}

		err = subFolderTreeNode.Save(database)

		if err != nil {
			return err
		}

		if len(messages) > 0 {
			Logger.Infof("Found %d messages.", len(messages))

			var kafkaMessages []kafka.Message

			for _, message := range messages {
				attachments, err := message.GetAttachments(&pstFile, formatType, encryptionType)

				if err != nil {
					return err
				}

				var pstAttachments []Attachment

				for _, attachment := range attachments {
					// Write attachment to disk and upload it to MinIO.
					attachmentFilename, err := attachment.GetFilename()

					if err != nil {
						Logger.Errorf("Failed to get attachment filename, using default: %s", err)
						attachmentFilename = "EMPTY_FILENAME"
					}

					pstAttachment := Attachment{
						UUID: NewUUID(),
						Name: attachmentFilename,
					}

					pstAttachments = append(pstAttachments, pstAttachment)

					err = attachment.WriteToFile(fmt.Sprintf("%s/%s", GetProjectTempDirectory(project.UUID), pstAttachment.UUID), &pstFile, formatType, encryptionType)

					if err != nil {
						Logger.Errorf("Failed to write attachment to file: %s", err)
						continue
					}

					_, err = UploadFile(pstAttachment.UUID, fmt.Sprintf("%s/%s", GetProjectTempDirectory(project.UUID), pstAttachment.UUID), project.UUID)

					if err != nil {
						Logger.Errorf("Failed to upload evidence: %s", err)
						return err
					}

					err = os.Remove(fmt.Sprintf("%s/%s", GetProjectTempDirectory(project.UUID), pstAttachment.UUID))

					if err != nil {
						Logger.Errorf("Failed to remove file: %s", err)
						return err
					}
				}

				pstMessage := createMessage(pstFile, message, project, subFolderTreeNode.FolderUUID, evidence, pstAttachments, formatType, encryptionType)

				kafkaMessages = append(kafkaMessages, kafka.Message{
					Key:   []byte(pstMessage.UUID),
					Value: []byte(pstMessage.JSON()),
				})

				if len(kafkaMessages) >= 100 {
					err := KafkaWriter.WriteMessages(context.Background(), kafkaMessages...)

					if err != nil {
						return err
					}

					kafkaMessages = []kafka.Message{}
				}
			}

			if len(kafkaMessages) > 0 {
				err := KafkaWriter.WriteMessages(context.Background(), kafkaMessages...)

				if err != nil {
					return err
				}
			}
		}

		err = parseSubFolders(pstFile, subFolder, formatType, encryptionType, project, evidence, database, subFolderTreeNode)

		if err != nil {
			return err
		}
	}

	return nil
}

// createMessage creates a message from the PST message which can be sent to Apache Kafka.
func createMessage(pstFile pst.File, message pst.Message, project Project, folderUUID string, evidence *Evidence, attachments []Attachment, formatType string, encryptionType string) Message {
	var pstMessage Message

	var bodyBuilder strings.Builder

	messageClass, err := message.GetMessageClass(&pstFile, formatType, encryptionType)

	if err == nil {
		if messageClass == "IPM.Appointment" {
			if allAttendees, err := message.GetAppointmentAllAttendees(&pstFile, formatType, encryptionType); err == nil {
				bodyBuilder.Write([]byte(fmt.Sprintf("All attendees: %s\n", allAttendees)))
			}

			if location, err := message.GetAppointmentLocation(&pstFile, formatType, encryptionType); err == nil {
				bodyBuilder.Write([]byte(fmt.Sprintf("Location: %s\n", location)))
			}

			if startTime, err := message.GetAppointmentStartTime(&pstFile); err == nil {
				bodyBuilder.Write([]byte(fmt.Sprintf("Start time: %s\n", startTime.String())))
			}

			if endTime, err := message.GetAppointmentEndTime(&pstFile); err == nil {
				bodyBuilder.Write([]byte(fmt.Sprintf("End time: %s\n", endTime.String())))
			}
		} else if messageClass == "IPM.Contact" {
			if givenName, err := message.GetContactGivenName(&pstFile, formatType, encryptionType); err == nil {
				bodyBuilder.Write([]byte(fmt.Sprintf("Given name: %s\n", givenName)))
			}

			if emailDisplayName, err := message.GetContactEmailDisplayName(&pstFile, formatType, encryptionType); err == nil {
				bodyBuilder.Write([]byte(fmt.Sprintf("Email display name: %s\n", emailDisplayName)))
			}

			if companyName, err := message.GetContactCompanyName(&pstFile, formatType, encryptionType); err == nil {
				bodyBuilder.Write([]byte(fmt.Sprintf("Company name: %s\n", companyName)))
			}

			if businessPhoneNumber, err := message.GetContactBusinessPhoneNumber(&pstFile, formatType, encryptionType); err == nil {
				bodyBuilder.Write([]byte(fmt.Sprintf("Business phone number: %s\n", businessPhoneNumber)))
			}

			if mobilePhoneNumber, err := message.GetContactMobilePhoneNumber(&pstFile, formatType, encryptionType); err == nil {
				bodyBuilder.Write([]byte(fmt.Sprintf("Mobile phone number: %s\n", mobilePhoneNumber)))
			}
		}
	}

	if bodyHTML, err := message.GetBodyHTML(&pstFile, formatType, encryptionType); err == nil {
		bodyBuilder.Write([]byte("\n"))
		bodyBuilder.Write([]byte(bodyHTML))
	} else {
		if body, err := message.GetBody(&pstFile, formatType, encryptionType); err == nil {
			bodyBuilder.Write([]byte("\n"))
			bodyBuilder.Write([]byte(body))
		}
	}

	pstMessage.Body = bodyBuilder.String()

	if subject, err := message.GetSubject(&pstFile, formatType, encryptionType); err == nil {
		pstMessage.Subject = subject
	}

	if from, err := message.GetFrom(&pstFile, formatType, encryptionType); err == nil {
		pstMessage.From = from
	}

	if to, err := message.GetTo(&pstFile, formatType, encryptionType); err == nil {
		pstMessage.To = to
	}

	if cc, err := message.GetCC(&pstFile, formatType, encryptionType); err == nil {
		pstMessage.CC = cc
	}

	if received, err := message.GetReceivedDate(); err == nil {
		pstMessage.Received = int(received.Unix())

		if pstMessage.Received < 0 {
			Logger.Error("Negative received date for message!")
			pstMessage.Received = 0
		}
	} else {
		Logger.Errorf("Failed to get received date: %s", err)
		pstMessage.Received = 0
	}

	if headers, err := message.GetHeaders(&pstFile, formatType, encryptionType); err == nil {
		pstMessage.Headers = headers
	}

	pstMessage.UUID = NewUUID()
	pstMessage.ProjectUUID = project.UUID
	pstMessage.Attachments = attachments
	pstMessage.FolderUUID = folderUUID
	pstMessage.EvidenceUUID = evidence.UUID

	return pstMessage
}
