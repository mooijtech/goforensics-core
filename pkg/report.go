// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import (
	_ "embed"
	"fmt"
	"html/template"
	"os"
)

//go:embed report.html
var reportTemplate string

//go:embed report_message.html
var reportMessageTemplate string

// CreateHTMLReport creates a report from the bookmarks.
// Returns the path to the created report ZIP file (stored in MinIO).
func CreateHTMLReport(messages []Message, project Project) (string, error) {
	reportTemplate, err := template.New("report").Parse(reportTemplate)

	if err != nil {
		return "", err
	}

	reportUUID := NewUUID()
	reportOutputDirectory := fmt.Sprintf("%s/%s", GetProjectTempDirectory(project.UUID), reportUUID)

	err = os.Mkdir(reportOutputDirectory, 0755)

	if err != nil {
		return "", err
	}

	reportOutputFile, err := os.Create(fmt.Sprintf("%s/report.html", reportOutputDirectory))

	if err != nil {
		return "", err
	}

	err = reportTemplate.Execute(reportOutputFile, map[string]interface{}{
		"project":  project,
		"messages": messages,
	})

	if err != nil {
		return "", err
	}

	for _, message := range messages {
		messageOutputFile, err := os.Create(fmt.Sprintf("%s/message-%s.html", reportOutputDirectory, message.UUID))

		if err != nil {
			return "", err
		}

		reportMessageTemplate, err := template.New("message").Parse(reportMessageTemplate)

		if err != nil {
			return "", err
		}

		err = reportMessageTemplate.Execute(messageOutputFile, map[string]interface{}{
			"project": project,
			"message": message,
		})

		if err != nil {
			return "", err
		}
	}

	err = ZipDirectory(reportOutputDirectory, fmt.Sprintf("%s/%s.zip", reportOutputDirectory, reportUUID))

	if err != nil {
		return "", err
	}

	uploadedFilePath, err := UploadFile(fmt.Sprintf("%s.zip", reportUUID), fmt.Sprintf("%s/%s.zip", reportOutputDirectory, reportUUID), project.UUID)

	if err != nil {
		return "", err
	}

	err = os.RemoveAll(reportOutputDirectory)

	if err != nil {
		return "", err
	}

	return uploadedFilePath, nil
}
