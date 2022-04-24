// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
)

// GetServerDatabase creates a new server database.
func GetServerDatabase() (*sql.DB, error) {
	database, err := sql.Open("sqlite3", fmt.Sprintf("data/goforensics.db"))

	if err != nil {
		return nil, err
	}

	return database, nil
}

// CreateServerDatabaseTables creates the server database tables.
func CreateServerDatabaseTables(database *sql.DB) error {
	tables := []string{
		"CREATE TABLE IF NOT EXISTS users(uuid TEXT PRIMARY KEY, email TEXT, password TEXT, last_seen TEXT)",
		"CREATE TABLE IF NOT EXISTS projects(uuid TEXT PRIMARY KEY, userUUID TEXT, name TEXT, password TEXT, memberUUIDs TEXT, creationDate INTEGER)",
	}

	for _, table := range tables {
		statement, err := database.Prepare(table)

		if err != nil {
			return err
		}

		_, err = statement.Exec()

		if err != nil {
			return err
		}
	}

	return nil
}

// GetProjectDatabase returns the database of the project.
func GetProjectDatabase(project Project) (*sql.DB, error) {
	database, err := sql.Open("sqlite3", fmt.Sprintf("data/users/%s/projects/%s/project.db", project.UserUUID, project.UUID))

	if err != nil {
		return nil, err
	}

	return database, nil
}

// CreateProjectDatabaseTables creates the project database tables.
func CreateProjectDatabaseTables(database *sql.DB) error {
	tables := []string{
		"CREATE TABLE IF NOT EXISTS evidence(uuid TEXT PRIMARY KEY, fileHash TEXT, fileName TEXT, isParsed TEXT)",
		"CREATE TABLE IF NOT EXISTS tree_nodes(folderUUID TEXT PRIMARY KEY, evidenceUUID TEXT, title TEXT, parent TEXT)",
		"CREATE TABLE IF NOT EXISTS bookmarks(messageUUID TEXT PRIMARY KEY)",
		"CREATE TABLE IF NOT EXISTS tags(messageUUID TEXT PRIMARY KEY, tag TEXT)",
	}

	for _, table := range tables {
		statement, err := database.Prepare(table)

		if err != nil {
			return err
		}

		_, err = statement.Exec()

		if err != nil {
			return err
		}
	}

	return nil
}
