// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import (
	"context"
	"fmt"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/spf13/viper"
	"io"
)

// Variables defining our MinIO client.
var (
	MinIOBucketName string
	MinIOClient     *minio.Client
)

// init initializes our MinIO client.
func init() {
	minioConfigurationVariables := []string{"minio_bucket", "minio_endpoint", "minio_access_key", "minio_secret_key", "minio_secure"}

	for _, configurationVariable := range minioConfigurationVariables {
		if !viper.IsSet(configurationVariable) {
			Logger.Fatalf("unset %s configuration variable", configurationVariable)
		}
	}

	minioClient, err := minio.New(viper.GetString("minio_endpoint"), &minio.Options{
		Creds:  credentials.NewStaticV4(viper.GetString("minio_access_key"), viper.GetString("minio_secret_key"), ""),
		Secure: viper.GetBool("minio_secure"),
	})

	if err != nil {
		Logger.Fatalf("Failed to get MinIO client: %s", err)
	}

	MinIOClient = minioClient
	MinIOBucketName = viper.GetString("minio_bucket")
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
