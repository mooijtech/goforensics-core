// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import (
	"context"
	"fmt"
	"github.com/minio/minio-go/v7"
	"os"
	"path/filepath"
	"strings"
)

// ExportAttachmentsByProject exports the attachments.
// Use "*" as the extensions to export all attachments.
func ExportAttachmentsByProject(extensions []string, projectUUID string) (string, error) {
	attachments, err := GetAllAttachments(projectUUID)

	if err != nil {
		return "", err
	}

	exportUUID := NewUUID()
	exportDirectory := fmt.Sprintf("%s/%s", GetProjectTempDirectory(projectUUID), exportUUID)

	err = os.Mkdir(exportDirectory, 0755)

	if err != nil {
		return "", err
	}

	// Write the attachments to the temp export directory.
	for _, attachment := range attachments {
		hasExtension := false

		for _, extension := range extensions {
			if extension == "*" {
				hasExtension = true
				break
			} else if filepath.Ext(attachment.Name) == extension {
				hasExtension = true
				break
			}
		}

		if hasExtension {
			err := MinIOClient.FGetObject(
				context.Background(),
				MinIOBucketName,
				fmt.Sprintf("%s/%s", projectUUID, attachment.UUID),
				fmt.Sprintf("%s/%s-%s%s", exportDirectory, strings.TrimSuffix(attachment.Name, filepath.Ext(attachment.Name)), attachment.UUID, filepath.Ext(attachment.Name)),
				minio.GetObjectOptions{},
			)

			if err != nil {
				if err.Error() == "The specified key does not exist." {
					// One of the parsers didn't upload the attachment to MinIO.
					Logger.Warnf("Failed to export attachment (%s - %s): %s", attachment.UUID, attachment.Name, err)
					continue
				} else {
					return "", err
				}
			}
		}
	}

	// ZIP the directory.
	err = ZipDirectory(exportDirectory, fmt.Sprintf("%s/%s.zip", GetProjectTempDirectory(projectUUID), exportUUID))

	if err != nil {
		return "", err
	}

	// Upload the ZIP file to MinIO.
	uploadedFilePath, err := UploadFile(fmt.Sprintf("%s.zip", exportUUID), fmt.Sprintf("%s/%s.zip", GetProjectTempDirectory(projectUUID), exportUUID), projectUUID)

	if err != nil {
		return "", err
	}

	return uploadedFilePath, nil
}
