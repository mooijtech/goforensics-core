// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import (
	"context"
	"fmt"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"io"
	"os"
	"strconv"
)

// Variables defining our MinIO client.
var (
	MinIOBucketName string
	MinIOClient     *minio.Client
)

// init initializes our MinIO client.
func init() {
	MinIOBucketName = os.Getenv("MINIO_BUCKET")

	if MinIOBucketName == "" {
		Logger.Fatal("unset MINIO_BUCKET environment variable")
	}

	endpoint := os.Getenv("MINIO_ENDPOINT")

	if endpoint == "" {
		Logger.Fatal("unset MINIO_ENDPOINT environment variable")
	}

	accessKey := os.Getenv("MINIO_ACCESS_KEY")

	if accessKey == "" {
		Logger.Fatal("unset MINIO_ACCESS_KEY environment variable")
	}

	secretKey := os.Getenv("MINIO_SECRET_KEY")

	if secretKey == "" {
		Logger.Fatal("unset MINIO_SECRET_KEY environment variable")
	}

	secure, err := strconv.ParseBool(os.Getenv("MINIO_SECURE"))

	if err != nil {
		Logger.Fatal("unset MINIO_SECURE environment variable")
	}

	minioClient, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: secure,
	})

	if err != nil {
		Logger.Fatalf("Failed to get MinIO client: %s", err)
	}

	MinIOClient = minioClient
}

// UploadFile uploads the file to MinIO and returns the MinIO path to the uploaded file.
func UploadFile(fileName string, filePath string, projectUUID string) (string, error) {
	objectName := fmt.Sprintf("%s/%s", projectUUID, fileName)
	contentType := "application/octet-stream"

	_, err := MinIOClient.FPutObject(context.Background(), MinIOBucketName, objectName, filePath, minio.PutObjectOptions{ContentType: contentType})

	if err != nil {
		return "", err
	}

	return objectName, nil
}

// GetObject returns the MinIO object.
func GetObject(objectName string) (*minio.Object, error) {
	objectReader, err := MinIOClient.GetObject(context.Background(), MinIOBucketName, objectName, minio.GetObjectOptions{})

	if err != nil {
		return nil, err
	}

	return objectReader, nil
}

// WriteFileToWriter writes the MinIO object to the writer.
func WriteFileToWriter(objectName string, writer io.Writer) error {
	objectReader, err := MinIOClient.GetObject(context.Background(), MinIOBucketName, objectName, minio.GetObjectOptions{})

	if err != nil {
		return err
	}

	written, err := io.Copy(writer, objectReader)

	if err != nil {
		Logger.Errorf("Failed to copy to writer (%d bytes written): %s", written, err)
		return err
	}

	return nil
}
