// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

// Project represents a user created project.
type Project struct {
	UUID         string   `json:"uuid"`
	UserUUID     string   `json:"user_uuid"`
	Name         string   `json:"name"`
	Password     string   `json:"password"`
	MemberUUIDs  []string `json:"members"`
	CreationDate int      `json:"creation_date"`
}

// Save saves the project to the database.
func (project *Project) Save(database *sql.DB) error {
	statement, err := database.Prepare("INSERT OR REPLACE INTO projects(uuid, userUUID, name, password, memberUUIDs, creationDate) VALUES (?,?,?,?,?,?)")

	if err != nil {
		return err
	}

	memberUUIDs, err := json.Marshal(project.MemberUUIDs)

	if err != nil {
		return err
	}

	_, err = statement.Exec(project.UUID, project.UserUUID, project.Name, project.Password, memberUUIDs, project.CreationDate)

	if err != nil {
		return err
	}

	return nil
}

// GetProjectByUUID returns the project with the specified UUID.
func GetProjectByUUID(projectUUID string, userUUID string, database *sql.DB) (Project, error) {
	rows, err := database.Query("SELECT * FROM projects WHERE uuid = ? AND userUUID = ?", projectUUID, userUUID)

	if err != nil {
		return Project{}, err
	}

	var project Project

	for rows.Next() {
		var memberUUIDs []byte

		err := rows.Scan(&project.UUID, &project.UserUUID, &project.Name, &project.Password, &memberUUIDs, &project.CreationDate)

		if err != nil {
			return Project{}, err
		}

		if err := json.Unmarshal(memberUUIDs, &project.MemberUUIDs); err != nil {
			return Project{}, err
		}
	}

	if project.UUID == "" {
		return Project{}, errors.New("failed to find project")
	}

	return project, nil
}

// GetProjectsByUserUUID returns all project from the specified user.
func GetProjectsByUserUUID(userUUID string, database *sql.DB) ([]Project, error) {
	rows, err := database.Query("SELECT * FROM projects WHERE userUUID = ?", userUUID)

	if err != nil {
		return nil, err
	}

	var projects []Project
	var project Project

	for rows.Next() {
		var memberUUIDs []byte

		err := rows.Scan(&project.UUID, &project.UserUUID, &project.Name, &project.Password, &memberUUIDs, &project.CreationDate)

		if err != nil {
			return nil, err
		}

		if err := json.Unmarshal(memberUUIDs, &project.MemberUUIDs); err != nil {
			return nil, err
		}

		projects = append(projects, project)
	}

	if len(projects) == 0 {
		return nil, errors.New("failed to find projects")
	}

	return projects, nil
}

// GetProjectDirectory returns the directory where the project is stored.
func GetProjectDirectory(project Project) string {
	return fmt.Sprintf("data/users/%s/projects/%s", project.UserUUID, project.UUID)
}

// GetProjectTempDirectory returns the directory where temporary files are files.
func GetProjectTempDirectory(project Project) string {
	return fmt.Sprintf("%s/tmp", GetProjectDirectory(project))
}
