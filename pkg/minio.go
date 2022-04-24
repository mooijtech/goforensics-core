// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import (
	"context"
	"errors"
	"fmt"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"io"
	"os"
	"strconv"
)

// Variable defining our MinIO client.
var (
	MinIOClient     *minio.Client
	MinIOBucketName string
)

// init initializes our MinIO client.
func init() {
	MinIOBucketName = os.Getenv("MINIO_BUCKET")

	if MinIOBucketName == "" {
		Logger.Fatal("Failed to get MinIO client: unset MINIO_BUCKET environment variable")
	}

	client, err := newMinIOClient()

	if err != nil {
		Logger.Fatalf("Failed to get MinIO client: %s", err)
	}

	MinIOClient = client
}

// newMinIOClient returns the MinIO client.
func newMinIOClient() (*minio.Client, error) {
	endpoint := os.Getenv("MINIO_ENDPOINT")

	if endpoint == "" {
		return nil, errors.New("unset MINIO_ENDPOINT environment variable")
	}

	accessKey := os.Getenv("MINIO_ACCESS_KEY")

	if accessKey == "" {
		return nil, errors.New("unset MINIO_ ACCESS_KEY environment variable")
	}

	secretKey := os.Getenv("MINIO_SECRET_KEY")

	if secretKey == "" {
		return nil, errors.New("unset MINIO_SECRET_KEY environment variable")
	}

	secure, err := strconv.ParseBool(os.Getenv("MINIO_SECURE"))

	if err != nil {
		return nil, errors.New("unset MINIO_SECURE environment variable")
	}

	minioClient, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: secure,
	})

	if err != nil {
		return nil, err
	}

	return minioClient, nil
}

// UploadFile uploads the file to MinIO and returns the MinIO path to the uploaded file.
func UploadFile(fileName string, filePath string, project Project) (string, error) {
	objectName := fmt.Sprintf("%s/%s/%s", project.UserUUID, project.UUID, fileName)
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
