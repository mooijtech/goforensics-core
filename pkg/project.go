// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v4"
)

// Project represents a user created project.
type Project struct {
	UUID         string `json:"uuid"`
	Name         string `json:"name"`
	CreationDate int    `json:"creation_date"`
}

// Save saves the project to the database.
func (project *Project) Save(database *pgx.Conn) error {
	preparedStatement := `
	INSERT INTO project(uuid, name, creationDate) VALUES ($1, $2, $3)
	`
	_, err := database.Exec(context.Background(), preparedStatement, project.UUID, project.Name, project.CreationDate)

	return err
}

// GetProjectByUUID returns the project with the specified UUID.
func GetProjectByUUID(projectUUID string, database *pgx.Conn) (Project, error) {
	preparedStatement := `
	SELECT * FROM project WHERE uuid = $1 LIMIT 1
	`
	row := database.QueryRow(context.Background(), preparedStatement, projectUUID)

	var project Project

	if err := row.Scan(&project.UUID, &project.Name, &project.CreationDate); err != nil {
		return Project{}, err
	}

	return project, nil
}

// GetProjectsByUser returns all project from the specified user.
func GetProjectsByUser(userUUID string, database *pgx.Conn) ([]Project, error) {
	preparedStatement := `
	SELECT p.uuid, p.name, p.creationDate FROM project_user_junction puj WHERE puj.userUUID = $1
	INNER JOIN project p ON p.uuid = puj.projectUUID
	`
	rows, err := database.Query(context.Background(), preparedStatement, userUUID)

	if err != nil {
		return nil, err
	}

	var projects []Project
	var project Project

	for rows.Next() {
		err := rows.Scan(&project.UUID, &project.Name, &project.CreationDate)

		if err != nil {
			return nil, err
		}

		projects = append(projects, project)
	}

	rows.Close()

	return projects, rows.Err()
}

// AddProjectEvidence adds the evidence to this project.
func AddProjectEvidence(projectUUID string, evidenceUUID string, database *pgx.Conn) error {
	preparedStatement := `
	INSERT INTO project_evidence_junction(projectUUID, evidenceUUID) VALUES ($1, $2)
	`
	_, err := database.Exec(context.Background(), preparedStatement, projectUUID, evidenceUUID)

	return err
}

// GetProjectDirectory returns the directory where the project related data is stored.
func GetProjectDirectory(projectUUID string) string {
	return fmt.Sprintf("data/projects/%s", projectUUID)
}

// GetProjectTempDirectory returns the directory where temporary files are stored.
func GetProjectTempDirectory(projectUUID string) string {
	return fmt.Sprintf("%s/tmp", GetProjectDirectory(projectUUID))
}
