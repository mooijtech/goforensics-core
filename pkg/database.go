// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import (
	"context"
	"github.com/jackc/pgx/v4"
	"os"
)

// DatabaseURL defines our PostgreSQL database URL.
var DatabaseURL string

func init() {
	DatabaseURL = os.Getenv("DATABASE_URL")

	if DatabaseURL == "" {
		Logger.Fatal("unset DATABASE_URL environment variable")
	}
}

// NewDatabase creates our Cassandra database session.
func NewDatabase() (*pgx.Conn, error) {
	connection, err := pgx.Connect(context.Background(), DatabaseURL)

	if err != nil {
		Logger.Fatalf("Failed to connect to database: %s", err)
	}

	return connection, nil
}

// CreateDatabaseTables creates all our database tables.
func CreateDatabaseTables(database *pgx.Conn) error {
	tables := []string{
		"CREATE TABLE IF NOT EXISTS project(uuid TEXT PRIMARY KEY, name TEXT, creationDate INTEGER)",
		"CREATE TABLE IF NOT EXISTS project_user_junction(id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, projectUUID TEXT NOT NULL REFERENCES project(uuid), userUUID TEXT NOT NULL)",
		"CREATE TABLE IF NOT EXISTS evidence(uuid TEXT PRIMARY KEY NOT NULL, fileHash TEXT NOT NULL, fileName TEXT NOT NULL, isParsed BOOLEAN)",
		"CREATE TABLE IF NOT EXISTS project_evidence_junction(id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, projectUUID TEXT NOT NULL REFERENCES project(uuid), evidenceUUID TEXT NOT NULL REFERENCES evidence(uuid))",
		"CREATE TABLE IF NOT EXISTS tree_node(folderUUID TEXT PRIMARY KEY NOT NULL, projectUUID TEXT NOT NULL REFERENCES project(uuid), evidenceUUID TEXT NOT NULL REFERENCES evidence(uuid), title TEXT, parentFolderUUID TEXT)",
		"CREATE TABLE IF NOT EXISTS message_metadata(messageUUID TEXT PRIMARY KEY, projectUUID TEXT NOT NULL REFERENCES project(uuid), isBookmarked BOOLEAN, tag TEXT, comment TEXT)",
	}

	for _, table := range tables {
		_, err := database.Exec(context.Background(), table)

		if err != nil {
			return err
		}
	}

	return nil
}
