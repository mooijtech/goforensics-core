// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import (
	"context"
	"fmt"
	"github.com/minio/minio-go/v7"
	"os"
	"path"
	"strings"
)

// ExportAttachments exports the attachments.
func ExportAttachments(extensions []string, project Project) (string, error) {
	attachments, err := GetAllAttachments(project)

	if err != nil {
		return "", err
	}

	exportUUID := NewUUID()
	exportDirectory := fmt.Sprintf("%s/%s", GetProjectTempDirectory(project), exportUUID)

	err = os.Mkdir(exportDirectory, 0755)

	if err != nil {
		return "", err
	}

	// Write the attachments to the export directory.
	for _, attachment := range attachments {
		hasExtension := false

		for _, extension := range extensions {
			if extension == "*" {
				hasExtension = true
				break
			} else if strings.HasSuffix(attachment.Name, extension) {
				hasExtension = true
				break
			}
		}

		if hasExtension {
			err := MinIOClient.FGetObject(
				context.Background(),
				MinIOBucketName,
				fmt.Sprintf("%s/%s/%s", project.UserUUID, project.UUID, attachment.UUID),
				fmt.Sprintf("%s/%s-%s%s", exportDirectory, strings.TrimSuffix(attachment.Name, path.Ext(attachment.Name)), attachment.UUID, path.Ext(attachment.Name)),
				minio.GetObjectOptions{},
			)

			if err != nil {
				if err.Error() == "The specified key does not exist." {
					Logger.Warnf("Failed to export attachment: %s", err)
					continue
				} else {
					return "", err
				}
			}
		}
	}

	// ZIP the directory.
	err = ZipDirectory(exportDirectory, fmt.Sprintf("%s/%s.zip", GetProjectTempDirectory(project), exportUUID))

	if err != nil {
		return "", err
	}

	// Upload the ZIP file to MinIO.
	_, err = UploadFile(fmt.Sprintf("%s.zip", exportUUID), fmt.Sprintf("%s/%s.zip", GetProjectTempDirectory(project), exportUUID), project)

	if err != nil {
		return "", err
	}

	Logger.Infof("Done exporting attachments.")

	return fmt.Sprintf("%s/%s/%s.zip", project.UserUUID, project.UUID, exportUUID), nil
}
