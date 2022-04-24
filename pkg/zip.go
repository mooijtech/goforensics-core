// Package core
// This file is part of Go Forensics (https://www.goforensics.io/)
// Copyright (C) 2022 Marten Mooij (https://www.mooijtech.com/)
package core

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Unzip unzips the ZIP file.
func Unzip(src string, dest string) error {
	zipReader, err := zip.OpenReader(src)

	if err != nil {
		return err
	}

	defer func() {
		if err := zipReader.Close(); err != nil {
			Logger.Errorf("Failed to close ZIP file: %s", err)
		}
	}()

	err = os.MkdirAll(dest, 0755)

	if err != nil {
		return err
	}

	extractAndWriteFile := func(zipFile *zip.File) error {
		inputFile, err := zipFile.Open()

		if err != nil {
			return err
		}

		defer func() {
			if err := inputFile.Close(); err != nil {
				Logger.Errorf("Failed to close file: %s", err)
			}
		}()

		path := filepath.Join(dest, zipFile.Name)

		// Check for ZipSlip (directory traversal)
		if !strings.HasPrefix(path, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path: %s", path)
		}

		if zipFile.FileInfo().IsDir() {
			err := os.MkdirAll(path, 0755)

			if err != nil {
				return err
			}
		} else {
			err := os.MkdirAll(filepath.Dir(path), 0755)

			if err != nil {
				return err
			}

			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)

			if err != nil {
				return err
			}

			defer func() {
				if err := f.Close(); err != nil {
					Logger.Errorf("Failed to close file: %s", err)
				}
			}()

			_, err = io.Copy(f, inputFile)

			if err != nil {
				return err
			}
		}

		return nil
	}

	for _, zipFile := range zipReader.File {
		err := extractAndWriteFile(zipFile)

		if err != nil {
			return err
		}
	}

	return nil
}

// ZipDirectory ZIPs the directory.
func ZipDirectory(pathToZip string, destinationPath string) error {
	destinationFile, err := os.Create(destinationPath)

	if err != nil {
		return err
	}

	zipWriter := zip.NewWriter(destinationFile)

	err = filepath.Walk(pathToZip, func(filePath string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}

		if err != nil {
			return err
		}

		relPath := strings.TrimPrefix(filePath, filepath.Dir(pathToZip))

		zipFile, err := zipWriter.Create(relPath)

		if err != nil {
			return err
		}

		fsFile, err := os.Open(filePath)

		if err != nil {
			return err
		}

		_, err = io.Copy(zipFile, fsFile)

		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return err
	}

	err = zipWriter.Close()

	if err != nil {
		return err
	}

	return nil
}
